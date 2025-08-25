import os
import xml.etree.ElementTree as ET
from app.decoders.decoder import Decoder, ScriptCodeDecoder

def load_wazuh_decoders(decoders_dir):
    decoders = []
    decoders_dir = os.path.expanduser(decoders_dir)

    if not os.path.isdir(decoders_dir):
        raise FileNotFoundError(f"[ERROR] Decoders directory not found: {decoders_dir}")

    print(f"[INFO] Loading decoders from: {decoders_dir}")

    for filename in os.listdir(decoders_dir):
        if not filename.endswith(".xml"):
            continue

        filepath = os.path.join(decoders_dir, filename)
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            for decoder_elem in root.findall("decoder"):
                name = decoder_elem.get("name", "UnnamedDecoder")
                program_elem = decoder_elem.find("program_name")
                regex_elem = decoder_elem.find("regex")

                if program_elem is None or regex_elem is None:
                    #print(f"[WARNING] Skipping decoder '{name}' in {filename}: missing <program_name> or <regex>")
                    continue

                program_name = program_elem.text.strip() if program_elem.text else ""
                regex = regex_elem.text.strip() if regex_elem.text else ""

                if not regex:
                    #print(f"[WARNING] Decoder '{name}' in {filename} has empty regex, skipping.")
                    continue

                decoder = Decoder(name, program_name, regex)
                decoders.append(decoder)
                print(f"[INFO] Loaded decoder: {name}")

        except ET.ParseError as e:
            print(f"[ERROR] Failed to parse XML file {filename}: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error loading {filename}: {e}")

    decoders.append(ScriptCodeDecoder())
    print("[INFO] ScriptCodeDecoder appended.")
    print(f"[INFO] Total decoders loaded: {len(decoders)}")
    return decoders


def build_decoder_lookup(decoders):
    """
    Build a dict for quick lookup by decoder name.
    """
    lookup = {}
    for decoder in decoders:
        lookup[decoder.name.lower()] = decoder
    return lookup




def apply_decoders(log, decoders):
    # If input is string, convert to dict with "message"
    if isinstance(log, str):
        log = {"message": log}

    print(f"[DEBUG] Raw log input: {log}")
    for decoder in decoders:
        if decoder.matches(log):
            #print(f"[DEBUG] Decoder matched: {decoder.name}")
            parsed_log = decoder.parse(log)
            #print(f"[DEBUG] Parsed log after decoding: {parsed_log}")
            return parsed_log, decoder
    print("[DEBUG] No decoder matched this log.")
    return log, None


def auto_detect_decoder_name(log: str, decoders: list) -> str | None:
    """
    Returns the name of the first decoder matching the log.
    """
    for decoder in decoders:
        if decoder.matches(log):
            print(f"[INFO] auto_detect_decoder_name matched: {decoder.name}")
            return decoder.name
    print("[INFO] auto_detect_decoder_name found no match.")
    return None

def match_log_with_decoders(log_text, decoders):
    """
    Matches a log text against all loaded decoders.
    Returns the parsed log if matched, else None.
    """
    parsed_log = apply_decoders(log_text, decoders)
    if parsed_log != log_text:
        return parsed_log
    return None

DECODERS_CACHE = load_wazuh_decoders("/home/kali/wazuh-ruleset/decoders")
DECODERS_LOOKUP = build_decoder_lookup(DECODERS_CACHE)
