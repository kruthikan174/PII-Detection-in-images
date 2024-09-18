from flask import Flask, render_template, request, redirect, url_for, send_file
from PIL import Image, ImageDraw
import pytesseract
from azure.ai.textanalytics import TextAnalyticsClient
from azure.core.credentials import AzureKeyCredential
import re
import io
import csv
from encryption_utils import encrypt_text, decrypt_text, generate_key_iv
from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors


# Replace with your Text Analytics key and endpoint
text_analytics_key = "c65fb48c6b434e549562e91aa70015e4"
text_analytics_endpoint = "https://kruthika.cognitiveservices.azure.com/"

# Initialize Text Analytics client
text_analytics_client = TextAnalyticsClient(
    endpoint=text_analytics_endpoint, credential=AzureKeyCredential(text_analytics_key)
)

app = Flask(__name__)

# Generate a key and IV (or load them from a secure place)
KEY, IV = generate_key_iv()

# Function to extract text from an image using Tesseract with bounding boxes
def extract_text_with_bounding_boxes(image_path):
    image = Image.open(image_path)
    data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
    return data

# Function to detect phone numbers using regex
def detect_phone_numbers(text):
    phone_pattern = r'\b\d{10}\b'
    matches = re.finditer(phone_pattern, text)
    phone_entities = [{'text': match.group(), 'category': 'PhoneNumber'} for match in matches]
    return phone_entities

# Function to detect PII using Azure Text Analytics
def detect_pii_in_text(text):
    documents = [text]
    response = text_analytics_client.recognize_pii_entities(documents=documents)[0]
    entities = [{'text': entity.text, 'category': entity.category} for entity in response.entities]
    return entities

# Function to save encrypted PII to a CSV file
def save_pii_to_csv(entities):
    with open('pii_data.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Text', 'Category', 'Encrypted Text'])  # Add header for encrypted text
        for entity in entities:
            encrypted_text = encrypt_text(entity['text'], KEY, IV)
            writer.writerow([entity['text'], entity['category'], encrypted_text.hex()])
    print("PII data saved to pii_data.csv.")

# Function to redact PII in the image
def redact_pii_in_image(image, data, entities_to_redact):
    draw = ImageDraw.Draw(image)

    # Prepare a set of entity texts to redact for easier matching
    entity_texts_to_redact = {entity['text'].lower().strip() for entity in entities_to_redact}

    # Loop through each word in the extracted text
    for i in range(len(data['text'])):
        word = data['text'][i].strip().lower()

        # Check if the word matches or partially matches any PII entity to redact
        if any(re.search(re.escape(entity_text), word) for entity_text in entity_texts_to_redact):
            # Get bounding box coordinates
            x, y, w, h = data['left'][i], data['top'][i], data['width'][i], data['height'][i]
            
            # Extend bounding box slightly for better coverage
            padding = 2
            x1, y1 = max(0, x - padding), max(0, y - padding)
            x2, y2 = x + w + padding, y + h + padding
            
            # Draw a black rectangle over the PII
            draw.rectangle(((x1, y1), (x2, y2)), fill="black")

    return image

@app.route("/", methods=["GET", "POST"])
def upload_image():
    if request.method == "POST":
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)

        if file:
            image = Image.open(file.stream)
            temp_path = "temp_image.png"
            image.save(temp_path)

            data = extract_text_with_bounding_boxes(temp_path)
            extracted_text = " ".join(data['text'])

            azure_entities = detect_pii_in_text(extracted_text)
            phone_entities = detect_phone_numbers(extracted_text)
            combined_entities = azure_entities + phone_entities

            save_pii_to_csv(combined_entities)

            return render_template("select_pii.html", entities=combined_entities, image_path=temp_path)

    return render_template("upload.html")

@app.route("/process_image", methods=["POST"])
def process_image():
    selected_entities = request.form.getlist("selected_pii")
    image_path = request.form['image_path']
    image = Image.open(image_path)
    
    data = extract_text_with_bounding_boxes(image_path)
    extracted_text = " ".join(data['text'])
    
    phone_entities = detect_phone_numbers(extracted_text)
    azure_entities = detect_pii_in_text(extracted_text)
    combined_entities = azure_entities + phone_entities

    entities_to_process = [entity for entity in combined_entities if entity['text'] in selected_entities]

    processed_image = redact_pii_in_image(image, data, entities_to_process)
    download_name = "masked_image.png"

    img_io = io.BytesIO()
    processed_image.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png', as_attachment=True, download_name=download_name)

if __name__ == "__main__":
    app.run(debug=True)
