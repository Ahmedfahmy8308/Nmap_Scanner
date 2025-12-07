import PyPDF2
import os

pdf_files = [
    r"m:\Coding projects\Intro_To_Sec_proj\Section 3\nmap_cheet_sheet.pdf",
    r"m:\Coding projects\Intro_To_Sec_proj\Section 3\Target Specification.pdf",
    r"m:\Coding projects\Intro_To_Sec_proj\Section 4\Scan techniques.pdf",
    r"m:\Coding projects\Intro_To_Sec_proj\Section 5\PortSpecification.pdf",
    r"m:\Coding projects\Intro_To_Sec_proj\Section 5\Service&Version Detection .pdf"
]

for pdf_path in pdf_files:
    print(f"\n{'='*80}")
    print(f"FILE: {os.path.basename(pdf_path)}")
    print(f"{'='*80}\n")
    
    try:
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            num_pages = len(pdf_reader.pages)
            print(f"Total pages: {num_pages}\n")
            
            for page_num in range(num_pages):
                page = pdf_reader.pages[page_num]
                text = page.extract_text()
                print(f"--- Page {page_num + 1} ---")
                print(text)
                print()
    except Exception as e:
        print(f"Error reading {pdf_path}: {e}")
        print()
