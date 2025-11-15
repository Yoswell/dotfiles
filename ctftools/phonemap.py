#!/usr/bin/env python3
"""
Phone Tab Decoder - Converts old phone keypad input to text.
Usage: python3 phonemap.py '11 222 3 5555'
"""
import sys

class Main:
    def get_phone_map():
        """Return the phone keypad mapping."""
        return {
            '2': [('A', 1), ('B', 2), ('C', 3)],
            '3': [('D', 1), ('E', 2), ('F', 3)],
            '4': [('G', 1), ('H', 2), ('I', 3)],
            '5': [('J', 1), ('K', 2), ('L', 3)],
            '6': [('M', 1), ('N', 2), ('O', 3)],
            '7': [('P', 1), ('Q', 2), ('R', 3), ('S', 4)],
            '8': [('T', 1), ('U', 2), ('V', 3)],
            '9': [('W', 1), ('X', 2), ('Y', 3), ('Z', 4)],
            '0': [(' ', 1)],
            ' ': [(' ', 1)]
        }

    def decode_phone_tabs(input_str):
        """
        Convert old phone keypad input to text.
        Example: '22 555 1 777' -> 'B L 1 R'
        """
        if not input_str.strip():
            return ""
            
        phone_map = get_phone_map()
        result = []
        
        for group in input_str.split(' '):
            if not group:
                result.append(' ')
                continue
                
            current_char = group[0]
            if current_char not in phone_map:
                result.append(current_char)
                continue
                
            char_list = phone_map[current_char]
            press_count = len(group)
            
            # Find the character that matches the number of presses
            found = False
            for char, required_presses in char_list:
                if press_count == required_presses:
                    result.append(char)
                    found = True
                    break
                    
            if not found:
                # If no exact match, use the last character in the list
                result.append(char_list[-1][0])
        
        return ' '.join(result)

    def main(self):
        if len(sys.argv) != 2:
            print("Usage: python3 phonemap.py '11 222 3 5555'")
            sys.exit(1)
            
        input_str = sys.argv[1]
        result = decode_phone_tabs(input_str)
        print(result)

if __name__ == "__main__":
    Main().main()
