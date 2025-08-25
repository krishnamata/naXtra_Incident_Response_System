# kb_extractor.py

import os
import xml.etree.ElementTree as ET
from app.rules.rules_loader import load_rules
from app.decoders.loader import load_wazuh_decoders

def extract_rule_texts(rules_dir: str):
    rules = load_rules(rules_dir)
    texts = []
    for rule in rules:
        text = rule.get('description', '') or rule.get('title', '')
        keywords = ' '.join(rule.get('keywords', []))
        combined_text = f"{text} {keywords}".strip()
        if combined_text:
            texts.append({
                'id': rule.get('id'),
                'type': 'rule',
                'text': combined_text,
                'metadata': {
                    'severity': rule.get('severity'),
                    'technique_id': rule.get('technique_id'),
                    'filename': rule.get('filename')
                }
            })
    return texts

def extract_decoder_texts(decoders_dir: str):
    decoders = load_wazuh_decoders(decoders_dir)
    texts = []
    for decoder in decoders:
        combined_text = f"{decoder.name} {decoder.program_name} {decoder.regex.pattern}"
        texts.append({
            'id': decoder.name,
            'type': 'decoder',
            'text': combined_text,
            'metadata': {}
        })
    return texts

def extract_alert_texts(alerts):
    # alerts: list of Alert objects or dicts with relevant fields
    texts = []
    for alert in alerts:
        desc = alert.description or ''
        rule_title = alert.rule_title or ''
        enrichment = alert.enrichment_data or ''
        combined_text = f"{rule_title} {desc} {enrichment}".strip()
        texts.append({
            'id': alert.id,
            'type': 'alert',
            'text': combined_text,
            'metadata': {
                'severity': alert.severity,
                'rule_id': alert.rule_id
            }
        })
    return texts
