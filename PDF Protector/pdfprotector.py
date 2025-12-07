import sys
from reportlab.pdfgen import canvas
import PyPDF2
import os

# step 1 create text to pdf 
def text_to_pdf(textfile,pdffile):
    c = canvas.Canvas(pdffile) 
    with open(textfile,'r',encoding="utf-8") as f:
        lines = f.readlines()

    left,top = 100, 800
    for line in lines:
        c.drawString(left,top, line.strip()) 
        top -=20
        if top < 50:
            c.showPage()
            top = 800
    c.save()
    print(f"PDF is created : {pdffile}")

#Step-2 PDF Encryption
def pdf_encryption(inputpdf,outputpdf,password):
    with open(inputpdf,'rb') as file:
        reader = PyPDF2.PdfReader(file)
        writer = PyPDF2.PdfWriter()

        for page in reader.pages:
            writer.add_page(page)
        
        writer.encrypt(password)
    
    with open(outputpdf,'wb') as output:
        writer.write(output)
    print(f"Encrypted Pdf saved: {outputpdf}")

#step-3 Logic
def main():
    if len(sys.argv) !=4:
        print("Enter in format : python script.py <inputtxtfile> <outputpdffile> <password>")
        sys.exit(1)
    text_file = sys.argv[1]
    output_pdf = sys.argv[2]
    password = sys.argv[3]
    temp_pdf = "temp.pdf"

    try:
        text_to_pdf(text_file, temp_pdf)       # Step 1: TXT -> PDF
        pdf_encryption(temp_pdf, output_pdf, password)  # Step 2: Encrypt PDF
        print("Task completed successfully!")

    finally:
        if os.path.exists(temp_pdf):   # Cleanup
            os.remove(temp_pdf)        # Temporary file delete
            print("Temporary file deleted")
if __name__ == "__main__":
    main()