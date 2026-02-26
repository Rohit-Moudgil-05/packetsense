"""
packetsense_rule_engine.py

Simple, safe rule engine for PacketSense.
- Supports YAML rule files stored in a `rules/` folder
- Two rule scopes: `flow` (applies to ML feature rows) and `packet` (applies to single packet dicts)
- Conditions are simple dictionaries: {field, op, value}
  supported ops:  >, <, >=, <=, ==, !=, in, not_in, contains, regex
- Action is a free-text field (e.g., 'alert', 'mark_mitre:T1046')

Usage (example, shown in app integration below):

    from packetsense_rule_engine import RuleEngine
    engine = RuleEngine(rules_dir='rules')
    matches = engine.apply_to_features(features_df)

The rules directory should contain YAML files describing rules. An example YAML is embedded at the bottom of this file.
"""

import os
import re
import glob
import json
from pathlib import Path
from typing import List, Dict, Any

try:
    import yaml
except Exception:
    yaml = None


class RuleEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.load_rules()

    def load_rules(self):
        self.rules = []
        if not self.rules_dir.exists():
            return
        for path in glob.glob(str(self.rules_dir / "*.yaml")) + glob.glob(str(self.rules_dir / "*.yml")):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    content = fh.read()
                    if yaml:
                        parsed = yaml.safe_load(content)
                    else:
                        # very small, limited YAML fallback for lists of dicts
                        parsed = self._tiny_yaml_parse(content)
                    if isinstance(parsed, list):
                        for r in parsed:
                            r['__source'] = path
                            self.rules.append(r)
                    elif isinstance(parsed, dict):
                        parsed['__source'] = path
                        self.rules.append(parsed)
            except Exception:
                continue

    def _tiny_yaml_parse(self, content: str):
        # Fallback parser: only supports very simple YAML rule lists (not recommended)
        # Return an empty list to avoid surprises
        return []

    @staticmethod
    def _compare(val, op, target):
        # normalize
        if op == '>':
            try:
                return float(val) > float(target)
            except Exception:
                return False
        if op == '<':
            try:
                return float(val) < float(target)
            except Exception:
                return False
        if op == '>=':
            try:
                return float(val) >= float(target)
            except Exception:
                return False
        if op == '<=':
            try:
                return float(val) <= float(target)
            except Exception:
                return False
        if op == '==':
            return str(val) == str(target)
        if op == '!=':
            return str(val) != str(target)
        if op == 'in':
            try:
                return val in target
            except Exception:
                return False
        if op == 'not_in':
            try:
                return val not in target
            except Exception:
                return False
        if op == 'contains':
            try:
                return str(target) in str(val)
            except Exception:
                return False
        if op == 'regex':
            try:
                return re.search(target, str(val)) is not None
            except Exception:
                return False
        return False

    def evaluate_conditions(self, row: Dict[str, Any], conditions: List[Dict[str, Any]]):
        # all conditions must be true (AND semantics)
        for cond in conditions:
            field = cond.get('field')
            op = cond.get('op', '==')
            target = cond.get('value')
            # read nested fields support: 'a.b'
            val = row.get(field)
            # if not present, fail the condition
            if val is None:
                return False
            if not self._compare(val, op, target):
                return False
        return True

    def apply_to_features(self, features_df):
        """Apply flow/feature rules to a pandas DataFrame of features (one row per flow).
        Returns a list of matches: [{rule_name, row_index, row_data, action, confidence}]"""
        matches = []
        flow_rules = [r for r in self.rules if r.get('scope','flow') in ('flow','both')]
        if not flow_rules:
            return matches
        # iterate rows
        try:
            import pandas as pd
        except Exception:
            pd = None
        for idx, row in (features_df.reset_index(drop=True)).iterrows():
            rdict = row.to_dict()
            for rule in flow_rules:
                conds = rule.get('conditions', [])
                if not conds:
                    continue
                try:
                    if self.evaluate_conditions(rdict, conds):
                        matches.append({
                            'rule': rule.get('name'),
                            'description': rule.get('description',''),
                            'index': int(idx),
                            'row': rdict,
                            'action': rule.get('action','alert'),
                            'confidence': rule.get('confidence', 0.5)
                        })
                except Exception:
                    continue
        return matches

    def apply_to_packets(self, packets_list: List[Dict[str, Any]]):
        """Apply packet rules to a list of packet dicts. Returns matches similar to apply_to_features"""
        matches = []
        packet_rules = [r for r in self.rules if r.get('scope','flow') in ('packet','both')]
        for i, pkt in enumerate(packets_list):
            for rule in packet_rules:
                conds = rule.get('conditions', [])
                if not conds:
                    continue
                try:
                    if self.evaluate_conditions(pkt, conds):
                        matches.append({
                            'rule': rule.get('name'),
                            'description': rule.get('description',''),
                            'packet_index': i,
                            'packet': pkt,
                            'action': rule.get('action','alert'),
                            'confidence': rule.get('confidence',0.6)
                        })
                except Exception:
                    continue
        return matches


# -------------------------
# Example rule YAML content
# -------------------------
# Save as rules/example_rules.yaml
#
# - name: High packet count flow
#   scope: flow
#   description: "Flow with many packets — possible DDoS source"
#   conditions:
#     - field: num_packets
#       op: '>'
#       value: 2000
#   action: alert
#   confidence: 0.95
#
# - name: Port scan heuristic
#   scope: flow
#   description: "Flow with many unique dst ports — scan"
#   conditions:
#     - field: unique_dst_ports
#       op: '>'
#       value: 50
#   action: alert
#   confidence: 0.8
#
# - name: Suspicious small-packet burst (packet rule)
#   scope: packet
#   description: "Very small packets to many destinations"
#   conditions:
#     - field: packet_len
#       op: '<'
#       value: 60
#   action: alert
#   confidence: 0.6

# Write example YAML file next to this module if rules folder doesn't exist
try:
    rules_dir = Path('rules')
    rules_dir.mkdir(exist_ok=True)
    example_path = rules_dir / 'example_rules.yaml'
    if not example_path.exists():
        example_path.write_text("""
- name: High packet count flow
  scope: flow
  description: "Flow with many packets — possible DDoS source"
  conditions:
    - field: num_packets
      op: '>'
      value: 2000
  action: alert
  confidence: 0.95

- name: Port scan heuristic
  scope: flow
  description: "Flow with many unique dst ports — scan"
  conditions:
    - field: unique_dst_ports
      op: '>'
      value: 50
  action: alert
  confidence: 0.8

- name: Suspicious small-packet burst (packet rule)
  scope: packet
  description: "Very small packets to many destinations"
  conditions:
    - field: packet_len
      op: '<'
      value: 60
  action: alert
  confidence: 0.6
""")
except Exception:
    pass
