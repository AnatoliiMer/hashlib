import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib

class HashCalculatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Калькулятор хеша файла")
        self.root.geometry("500x250")
        
        # Переменные
        self.file_path = tk.StringVar()
        self.hash_result = tk.StringVar()
        self.algorithm = tk.StringVar(value="sha256")
        
        # Создание виджетов
        self.create_widgets()
    
    def create_widgets(self):
        # Фрейм для выбора файла
        file_frame = ttk.LabelFrame(self.root, text="Выбор файла")
        file_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Entry(file_frame, textvariable=self.file_path, state="readonly").pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(file_frame, text="Обзор...", command=self.browse_file).pack(side="left", padx=5)
        
        # Фрейм для выбора алгоритма
        algo_frame = ttk.LabelFrame(self.root, text="Алгоритм хеширования")
        algo_frame.pack(pady=10, padx=10, fill="x")
        
        algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
        for algo in algorithms:
            ttk.Radiobutton(algo_frame, text=algo.upper(), variable=self.algorithm, value=algo).pack(side="left", padx=5)
        
        # Кнопка расчета
        ttk.Button(self.root, text="Рассчитать хеш", command=self.calculate_hash).pack(pady=10)
        
        # Фрейм для результата
        result_frame = ttk.LabelFrame(self.root, text="Результат")
        result_frame.pack(pady=10, padx=10, fill="x")
        
        ttk.Entry(result_frame, textvariable=self.hash_result, state="readonly", font=('Arial', 10)).pack(fill="x", padx=5, pady=5)
        
        # Кнопка копирования
        ttk.Button(result_frame, text="Копировать", command=self.copy_to_clipboard).pack(pady=5)
    
    def browse_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.file_path.set(filepath)
            self.hash_result.set("")  # Очищаем предыдущий результат
    
    def calculate_hash(self):
        filepath = self.file_path.get()
        if not filepath:
            messagebox.showwarning("Ошибка", "Пожалуйста, выберите файл")
            return
        
        try:
            hash_value = self.calculate_file_hash(filepath, self.algorithm.get())
            self.hash_result.set(hash_value)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось рассчитать хеш:\n{str(e)}")
    
    def calculate_file_hash(self, file_path, algorithm='sha256'):
        """Вычисляет хеш файла с использованием указанного алгоритма"""
        hash_algo = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_algo.update(chunk)
        
        return hash_algo.hexdigest()
    
    def copy_to_clipboard(self):
        hash_value = self.hash_result.get()
        if hash_value:
            self.root.clipboard_clear()
            self.root.clipboard_append(hash_value)
            messagebox.showinfo("Успех", "Хеш скопирован в буфер обмена")

if __name__ == "__main__":
    root = tk.Tk()
    app = HashCalculatorApp(root)
    root.mainloop()