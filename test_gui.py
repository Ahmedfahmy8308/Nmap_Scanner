"""
Test GUI Launch
"""
import customtkinter as ctk

print("Creating window...")
root = ctk.CTk()
root.title("Test Window")
root.geometry("400x300")

label = ctk.CTkLabel(root, text="GUI is Working!", font=("Arial", 20))
label.pack(pady=50)

button = ctk.CTkButton(root, text="Click Me", command=lambda: print("Button clicked!"))
button.pack(pady=20)

print("Starting mainloop...")
root.mainloop()
print("Window closed")
