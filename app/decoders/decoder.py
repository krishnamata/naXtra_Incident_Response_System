import re

#decodes and programming language, scripts etc

class Decoder:
    """
    Base Decoder class initialized with a name, program name, and regex pattern.
    Provides methods to check if the log matches the pattern and parse fields.
    """
    def __init__(self, name, program_name, regex):
        self.name = name
        self.program_name = program_name
        self.regex = re.compile(regex)

    def matches(self, log):
        """
        Check if the regex pattern matches the log's 'message' field.
        """
        msg = log.get("message", "")
        return bool(self.regex.search(msg))

    def parse(self, log):
        """
        Extract regex groups from the message and merge them into the log dictionary.
        Returns extended log dict with extracted fields added.
        """
        msg = log.get("message", "")
        match = self.regex.search(msg)
        if match:
            if match.groupdict():
                fields = match.groupdict()
            else:
                fields = {f"group{i+1}": val for i, val in enumerate(match.groups())}
            return {**log, **fields}
        return log


class ScriptCodeDecoder(Decoder):
    """
    Decoder to detect scripting or programming code within log messages.
    Uses language-specific regex patterns and overrides matches() and parse().
    """
    def __init__(self, name="ScriptCodeDetector"):
        super().__init__(name, program_name="script_detector", regex="")  # regex unused here

        # Pre-compile language-specific regex patterns for performance
        self.patterns = {
            'powershell': re.compile(r'\b(powershell|Invoke-Expression|IEX|New-Object|-enc)\b', re.IGNORECASE),
            'javascript': re.compile(r'\b(function\s+\w+|eval\s*\(|document\.write)\b', re.IGNORECASE),
            'python': re.compile(r'\b(import\s+\w+|def\s+\w+\(|os\.system)\b', re.IGNORECASE),
            'dotnet': re.compile(r'\b(System\.Reflection|DllImport|Assembly\.Load)\b', re.IGNORECASE),
            'bash': re.compile(r'\b(eval|exec|wget|curl)\b\s+http[s]?://', re.IGNORECASE),
        }

    def matches(self, log):
        """
        Return True if any scripting language pattern is found in the log's message.
        """
        msg = log.get("message", "")
        return any(pattern.search(msg) for pattern in self.patterns.values())

    def parse(self, log):
        """
        Detects scripting language present in the log's message.
        Adds 'decoded_as' and 'detected_script' fields indicating the language detected or 'none'.
        """
        msg = log.get("message", "")
        for lang, pattern in self.patterns.items():
            if pattern.search(msg):
                return {**log, "decoded_as": f"script:{lang}", "detected_script": lang}
        return {**log, "decoded_as": "script:none", "detected_script": "none"}
