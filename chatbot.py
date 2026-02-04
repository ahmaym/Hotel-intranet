"""
Hotel Intranet Chatbot Module
Intent-based chatbot with pattern matching for hotel staff assistance
"""

import json
import re
import random
from difflib import SequenceMatcher
import os

class HotelChatbot:
    def __init__(self, data_file='chatbot_data.json'):
        self.intents = []
        self.department_contacts = {}
        self.load_data(data_file)
    
    def load_data(self, data_file):
        """Load chatbot training data from JSON file"""
        try:
            # Get the directory where this script is located
            base_dir = os.path.dirname(os.path.abspath(__file__))
            file_path = os.path.join(base_dir, data_file)
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.intents = data.get('intents', [])
                self.department_contacts = data.get('department_contacts', {})
        except FileNotFoundError:
            print(f"Warning: {data_file} not found. Chatbot will have limited functionality.")
            self.intents = []
        except json.JSONDecodeError:
            print(f"Warning: {data_file} is not valid JSON.")
            self.intents = []
    
    def preprocess(self, text):
        """Clean and normalize input text"""
        # Convert to lowercase
        text = text.lower().strip()
        # Remove punctuation except apostrophes
        text = re.sub(r"[^\w\s']", ' ', text)
        # Remove extra whitespace
        text = ' '.join(text.split())
        return text
    
    def calculate_similarity(self, text1, text2):
        """Calculate similarity ratio between two strings"""
        return SequenceMatcher(None, text1, text2).ratio()
    
    def find_best_match(self, user_input):
        """Find the best matching intent for user input"""
        processed_input = self.preprocess(user_input)
        words = set(processed_input.split())
        
        best_match = None
        best_score = 0
        
        for intent in self.intents:
            if intent['tag'] == 'unknown':
                continue
                
            for pattern in intent.get('patterns', []):
                processed_pattern = self.preprocess(pattern)
                pattern_words = set(processed_pattern.split())
                
                # Method 1: Exact match
                if processed_input == processed_pattern:
                    return intent, 1.0
                
                # Method 2: Input contains pattern
                if processed_pattern in processed_input:
                    score = 0.9
                    if score > best_score:
                        best_score = score
                        best_match = intent
                
                # Method 3: Pattern contains input
                if processed_input in processed_pattern and len(processed_input) > 3:
                    score = 0.85
                    if score > best_score:
                        best_score = score
                        best_match = intent
                
                # Method 4: Word overlap
                if words and pattern_words:
                    overlap = len(words & pattern_words)
                    total = len(words | pattern_words)
                    jaccard = overlap / total if total > 0 else 0
                    
                    # Boost score if key words match
                    key_word_bonus = 0
                    key_words = ['leave', 'wifi', 'password', 'pay', 'salary', 'help', 
                                'emergency', 'parking', 'food', 'training', 'complaint',
                                'check', 'room', 'guest', 'it', 'hr', 'benefit']
                    for kw in key_words:
                        if kw in words and kw in pattern_words:
                            key_word_bonus = 0.2
                            break
                    
                    score = jaccard + key_word_bonus
                    if score > best_score:
                        best_score = score
                        best_match = intent
                
                # Method 5: Sequence similarity
                similarity = self.calculate_similarity(processed_input, processed_pattern)
                if similarity > best_score:
                    best_score = similarity
                    best_match = intent
        
        return best_match, best_score
    
    def get_department_info(self, department_name):
        """Get contact info for a specific department"""
        for dept, info in self.department_contacts.items():
            if department_name.lower() in dept.lower():
                return f"**{dept} Department:**\n- Extension: {info['extension']}\n- Email: {info['email']}\n- Location: {info['location']}"
        return None
    
    def get_response(self, user_input):
        """Generate a response for the user input"""
        if not user_input or not user_input.strip():
            return "Please type a message to get started!"
        
        # Check for department contact queries
        dept_keywords = ['contact', 'reach', 'call', 'email', 'find', 'where is']
        for keyword in dept_keywords:
            if keyword in user_input.lower():
                for dept in self.department_contacts.keys():
                    if dept.lower() in user_input.lower():
                        return self.get_department_info(dept)
        
        # Find best matching intent
        intent, score = self.find_best_match(user_input)
        
        # Threshold for accepting a match
        if intent and score >= 0.3:
            responses = intent.get('responses', [])
            if responses:
                return random.choice(responses)
        
        # No good match found - return unknown response
        for intent in self.intents:
            if intent['tag'] == 'unknown':
                return random.choice(intent.get('responses', ["I'm not sure how to help with that. Please try rephrasing your question."]))
        
        return "I'm sorry, I don't have information on that topic. Please contact HR or your supervisor for assistance."
    
    def get_quick_actions(self):
        """Return list of quick action suggestions"""
        return [
            {"label": "Leave Policy", "query": "What is the leave policy?"},
            {"label": "WiFi Password", "query": "What is the WiFi password?"},
            {"label": "IT Support", "query": "How do I contact IT support?"},
            {"label": "Emergency", "query": "Emergency contacts"},
            {"label": "Benefits", "query": "What are the employee benefits?"},
            {"label": "Payroll", "query": "When is payday?"},
            {"label": "Training", "query": "Training programs available"},
            {"label": "Meeting Rooms", "query": "How to book a meeting room?"}
        ]


# Singleton instance
_chatbot_instance = None

def get_chatbot():
    """Get or create chatbot instance"""
    global _chatbot_instance
    if _chatbot_instance is None:
        _chatbot_instance = HotelChatbot()
    return _chatbot_instance
