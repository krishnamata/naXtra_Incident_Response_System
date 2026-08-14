import os
import xml.etree.ElementTree as ET
from app.decoders.decoder import Decoder, ScriptCodeDecoder

def load_wazuh_decoders(decoders_dir):
    decoders = []
    decoders_dir = os.path.expanduser(decoders_dir)

    if not os.path.isdir(decoders_dir):
        raise FileNotFoundError(f"[ERROR] Decoders directory not found: {decoders_dir}")

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
                platform_elem = decoder_elem.find("platform")  # Optional: linux/windows/network

                program_name = program_elem.text.strip() if program_elem is not None and program_elem.text else ""
                regex = regex_elem.text.strip() if regex_elem is not None and regex_elem.text else ""
                platform = platform_elem.text.strip().lower() if platform_elem is not None and platform_elem.text else None

                # Skip decoders with neither program_name nor regex
                if not program_name and not regex:
                    continue

                decoder = Decoder(name, program_name, regex)
                decoder.platform = platform  # attach platform info
                decoders.append(decoder)
                print(f"[INFO] Loaded decoder: {name} (Platform: {platform})")

        except ET.ParseError as e:
            print(f"[ERROR] Failed to parse XML file {filename}: {e}")
        except Exception as e:
            print(f"[ERROR] Unexpected error loading {filename}: {e}")

    # Add ScriptCodeDecoder at the end (generic fallback)
    decoders.append(ScriptCodeDecoder())
    decoders[-1].platform = None
    print("[INFO] ScriptCodeDecoder appended.")

    # --- PRIORITIZE CRON decoders ---
    decoders.sort(key=lambda d: 0 if d.name.startswith("cron-service") else 1)

    print(f"[INFO] Total decoders loaded: {len(decoders)}")
    return decoders


def build_decoder_lookup(decoders):
    """
    Build a dict for quick lookup by decoder name.
    """
    return {decoder.name.lower(): decoder for decoder in decoders}


def apply_decoders(log, decoders, agent_type=None):
    """
    Apply decoders to a log.
    If agent_type is provided, only decoders for that platform or generic will be considered.
    Returns (parsed_log, decoder) or (original log, None)
    """
    if isinstance(log, str):
        log = {"message": log}

    for decoder in decoders:
        if agent_type and decoder.platform and decoder.platform != agent_type:
            continue
        if decoder.matches(log):
            parsed_log = decoder.parse(log)
            return parsed_log, decoder

    # No matching decoder found; fallback to generic
    for decoder in decoders:
        if decoder.platform is None and decoder.matches(log):
            parsed_log = decoder.parse(log)
            return parsed_log, decoder

    return log, None


def auto_detect_decoder_name(log, decoders, agent_type=None):
    """
    Returns the name of the first decoder matching the log.
    """
    parsed_log, decoder = apply_decoders(log, decoders, agent_type)
    return decoder.name if decoder else None


def match_log_with_decoders(log_text, decoders, agent_type=None):
    """
    Matches a log text against all loaded decoders.
    Returns a tuple (parsed_log, decoder) if matched, else (log_text, None).
    """
    return apply_decoders(log_text, decoders, agent_type)


# --- LOAD DECODERS ---
DECODERS_CACHE = load_wazuh_decoders("app/rules/wazuh-ruleset/decoders")
DECODERS_LOOKUP = build_decoder_lookup(DECODERS_CACHE)
