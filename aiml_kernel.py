import xml.etree.ElementTree as ET
import re
import os

class AimlKernel:
    def __init__(self):
        self._patterns = {} # For exact matches
        self._wildcard_patterns = [] # For wildcard matches

    def learn(self, filepath):
        """Loads and parses AIML files from a directory."""
        for root, dirs, files in os.walk(filepath):
            for file in files:
                if file.endswith(".aiml"):
                    tree = ET.parse(os.path.join(root, file))
                    aiml_root = tree.getroot()
                    self._parse_aiml(aiml_root)

    def _parse_aiml(self, aiml_root):
        """Extracts patterns and templates from AIML elements."""
        for category in aiml_root.findall('category'):
            pattern_element = category.find('pattern')
            template_element = category.find('template')
            
            if pattern_element is not None and template_element is not None:
                pattern = pattern_element.text.strip().upper()
                template = template_element.text.strip() if template_element.text else ""
                
                # Handle nested tags in template (like <star/>)
                for child in template_element:
                    if child.tag == 'star':
                        # Placeholder for star replacement
                        template += f"__STAR{child.attrib.get('index', '1')}__"
                    if child.tail:
                        template += child.tail.strip()

                if '*' in pattern or '_' in pattern:
                    self._wildcard_patterns.append((pattern, template))
                else:
                    self._patterns[pattern] = template

    def respond(self, user_input):
        """Finds a response for the user's input."""
        cleaned_input = user_input.upper().strip()

        # 1. Check for an exact match first
        if cleaned_input in self._patterns:
            return self._patterns[cleaned_input]

        # 2. Check for a wildcard match
        for pattern, template in self._wildcard_patterns:
            # Convert AIML wildcard to regex
            regex_pattern = pattern.replace('*', '(.+)').replace('_', '(.+)')
            match = re.fullmatch(regex_pattern, cleaned_input)

            if match:
                # We found a match, now process the template
                response = template
                # Replace <star/> placeholders with captured groups
                for i, group in enumerate(match.groups(), 1):
                    response = response.replace(f"__STAR{i}__", group)
                return response
        
        return "I don't have an answer for that."