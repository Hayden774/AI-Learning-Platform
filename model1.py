import random
import fitz  # PyMuPDF library for extracting text from PDFs
import re
from collections import defaultdict
import spacy  # SpaCy for NLP processing
import os
import google.generativeai as genai  # Import the Gemini API
import io
import PyPDF2

class Chatbot:
    def __init__(self):
        # Initialize an empty knowledge base and NLP model
        self.knowledge_base = defaultdict(list)  # Store multiple entries for each keyword
        self.extracted_sentences = []  # Stores extracted sentences from PDFs
        self.nlp = spacy.load("en_core_web_sm")  # Load spaCy's English model for NLP tasks
        self.configure_api()

    def configure_api(self):
        """
        Configure the Gemini API with the API key.
        """
        os.environ["API_KEY"] = "AIzaSyDGlAElyHM6UbCHTRqPTmxmsza-_Xo33T0"  
        genai.configure(api_key=os.environ["API_KEY"])

    def extract_text_from_pdf(self, pdf_file):
        import PyPDF2
        reader = PyPDF2.PdfReader(pdf_file)
        text = ""
        for page in reader.pages:
            text += page.extract_text() + "\n"
        self.extracted_sentences = text.split('. ')  # Store sentences for later use
        return "Text extracted successfully from PDF."

    def set_extracted_content(self, text):
        # Assuming `text` is a single string, split into sentences
        self.extracted_sentences = re.split(r'\.\s+', text)  # Better splitting for sentences

    def _build_knowledge_base(self):
        """
        Builds a knowledge base from extracted sentences by identifying keywords.
        Uses spaCy NLP to categorize sentences based on common IT and CS topics.
        """
        # Check if sentences are being extracted properly
        print(f"Extracted {len(self.extracted_sentences)} sentences from the PDF.")

        for sentence in self.extracted_sentences:
            doc = self.nlp(sentence)  # Process the sentence with spaCy
            matched = False  # Track if a keyword matched

            for token in doc:
                # Access the token's text to categorize sentences into different knowledge areas based on keywords
                token_text = token.text.lower()  # Access token text once
                
                # Categorize sentences based on keywords
                if any(word in token_text for word in ["cpu", "processor", "core"]):
                    self.knowledge_base["cpu"].append(sentence)
                    matched = True
                    break  # Stop checking once a match is found
                elif any(word in token_text for word in ["ram", "memory"]):
                    self.knowledge_base["ram"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["http", "web", "internet"]):
                    self.knowledge_base["http"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["artificial intelligence", "ai"]):
                    self.knowledge_base["artificial intelligence"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["machine learning", "ml"]):
                    self.knowledge_base["machine learning"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["deep learning", "neural network"]):
                    self.knowledge_base["deep learning"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["natural language processing", "nlp"]):
                    self.knowledge_base["natural language processing"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["computer vision", "image recognition"]):
                    self.knowledge_base["computer vision"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["data science", "data analysis"]):
                    self.knowledge_base["data science"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["programming", "coding"]):
                    self.knowledge_base["programming"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["web development", "frontend", "backend"]):
                    self.knowledge_base["web development"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["database", "sql", "nosql"]):
                    self.knowledge_base["databases"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["cloud computing", "aws", "azure"]):
                    self.knowledge_base["cloud computing"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["cybersecurity", "security", "encryption"]):
                    self.knowledge_base["cybersecurity"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["networking", "network", "protocol"]):
                    self.knowledge_base["networking"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["operating system", "os", "linux", "windows"]):
                    self.knowledge_base["operating systems"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["algorithm", "sort", "search"]):
                    self.knowledge_base["algorithms"].append(sentence)
                    matched = True
                    break
                elif any(word in token_text for word in ["data structure", "array", "list", "tree"]):
                    self.knowledge_base["data structures"].append(sentence)
                    matched = True
                    break

            # Debug statement to check if a sentence matched any category
            if matched:
                print(f"Matched sentence: {sentence}")
            else:
                print(f"No match for: {sentence}")

    def teach(self, user_input):
        """
        Responds to user's IT-related questions using the Gemini API.
        Calls the Gemini API for a more dynamic response.
        Returns only the generated answer.
        """
        user_input = user_input.strip()
        if not user_input:
            return "Please ask a valid question."

        # Generate a response using the Gemini API
        try:
            model = genai.GenerativeModel("gemini-1.5-flash")
            response = model.generate_content(user_input)
            
            # Return just the AI-generated response text
            return response.text
        except Exception as e:
            return f"An error occurred: {str(e)}"



    def generate_quiz_question(self):
        if not self.extracted_sentences:
            return {"question": "No content available to generate questions.", "answer": ""}
        
        sentence = random.choice(self.extracted_sentences)
        # Create a simple quiz question (modify this to fit your needs)
        return {
            "question": f"What does the following sentence mean? {sentence}",
            "answer": "The expected answer here."  # You can improve this
        }

    def evaluate_quiz_answer(self, user_answer, correct_answer):
        """
        Evaluates the user's answer against the correct answer.
        Provides feedback on whether the answer is correct or not.
        """
        # Simple evaluation logic (modify this to fit your needs)
        is_correct = user_answer.lower() == correct_answer.lower()
        feedback = "Correct!" if is_correct else f"Incorrect! The correct answer was: {correct_answer}"
        return is_correct, feedback

    def chat(self, user_input):
        """
        Main interaction method. Decides whether to teach or quiz based on user input.
        If 'quiz' is mentioned, it generates a quiz question; otherwise, it provides information.
        """
        if "quiz" in user_input.lower():
            question_data = self.generate_quiz_question()
            # Ensure question_data is a dict and contains the expected keys
            if isinstance(question_data, dict) and "question" in question_data:
                return {
                    "type": "quiz",
                    "question": question_data["question"],
                    "answer": question_data.get("answer", "")
                }
            else:
                return {
                    "type": "error",
                    "message": "Error generating quiz question."
                }
        else:
            # Call the teach method and return only the generated answer
            response = self.teach(user_input)
            return response 
