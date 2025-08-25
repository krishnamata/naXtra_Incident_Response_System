# app/utils/unique_id_manager.py

import os
import xml.etree.ElementTree as ET
from lxml import etree

class UniqueIDManager:
    """
    Manages unique IDs and names for rules and decoders.
    Also validates XML against own schemas before saving.
    """

    def __init__(self, kb_indexer, schema_dir="schemas"):
        self.kb_indexer = kb_indexer
        self.schema_dir = schema_dir

        # Collect existing IDs/names from KB
        self.rule_ids = set(kb_indexer.get_all_rule_ids())
        self.decoder_ids = set(kb_indexer.get_all_decoder_ids())
        self.rule_names = set(kb_indexer.get_all_rule_names())
        self.decoder_names = set(kb_indexer.get_all_decoder_names())

        # Safe starting ranges (customize as needed)
        self.rule_id_start = 100000   # avoid collision with legacy IDs
        self.decoder_id_start = 1000

    # ------------------ ID GENERATORS ------------------

    def get_next_id(self, prefix="r"):
        """
        Returns the next unique ID for a rule (prefix='r') or decoder (prefix='d').
        Format: r##### or d#####.
        """
        if prefix == "r":
            new_id = self.rule_id_start
            while new_id in self.rule_ids:
                new_id += 1
            self.rule_ids.add(new_id)
            self.rule_id_start = new_id + 1
            return f"r{new_id:05d}"

        elif prefix == "d":
            new_id = self.decoder_id_start
            while new_id in self.decoder_ids:
                new_id += 1
            self.decoder_ids.add(new_id)
            self.decoder_id_start = new_id + 1
            return f"d{new_id:05d}"

        else:
            raise ValueError(f"Invalid prefix '{prefix}' for unique ID. Use 'r' or 'd'.")





    # ------------------ NAME CHECK ------------------

    def is_name_conflict(self, name, is_rule=True):
        if is_rule:
            return name in self.rule_names
        return name in self.decoder_names

    def register_name(self, name, is_rule=True):
        if is_rule:
            self.rule_names.add(name)
        else:
            self.decoder_names.add(name)

    # ------------------ SCHEMA VALIDATION ------------------

    def validate_xml(self, xml_path, xml_type="rule"):
        """
        Validate XML file against own schema.
        xml_type = "rule" or "decoder"
        """
        if xml_type == "rule":
            schema_file = os.path.join(self.schema_dir, "rules_own.xsd")
        elif xml_type == "decoder":
            schema_file = os.path.join(self.schema_dir, "decoders_own.xsd")
        else:
            raise ValueError("Invalid xml_type. Use 'rule' or 'decoder'.")

        if not os.path.exists(schema_file):
            raise FileNotFoundError(f"Schema file not found: {schema_file}")

        with open(schema_file, "rb") as f:
            schema_root = etree.XML(f.read())
        schema = etree.XMLSchema(schema_root)

        parser = etree.XMLParser(schema=schema)
        try:
            with open(xml_path, "rb") as xf:
                etree.fromstring(xf.read(), parser)
            return True
        except etree.XMLSyntaxError as e:
            print(f"[ERROR] XML validation failed: {e}")
            return False

    # ------------------ INLINE VALIDATION (from string) ------------------

    def validate_xml_string(self, xml_string, xml_type="rule"):
        if xml_type == "rule":
            schema_file = os.path.join(self.schema_dir, "rules_own.xsd")
        elif xml_type == "decoder":
            schema_file = os.path.join(self.schema_dir, "decoders_own.xsd")
        else:
            raise ValueError("Invalid xml_type. Use 'rule' or 'decoder'.")

        if not os.path.exists(schema_file):
            raise FileNotFoundError(f"Schema file not found: {schema_file}")

        with open(schema_file, "rb") as f:
            schema_root = etree.XML(f.read())
        schema = etree.XMLSchema(schema_root)

        parser = etree.XMLParser(schema=schema)
        try:
            etree.fromstring(xml_string.encode(), parser)
            return True
        except etree.XMLSyntaxError as e:
            print(f"[ERROR] XML string validation failed: {e}")
            return False
