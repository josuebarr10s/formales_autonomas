import sys
import re
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget,
    QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem, QLabel
)
from PyQt6.QtGui import QFont, QColor, QSyntaxHighlighter, QTextCharFormat
from PyQt6.QtCore import Qt, QRegularExpression

class CodigoHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self._highlighting_rules = []

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#FF9800"))  # Naranja para palabras reservadas
        keyword_format.setFontWeight(QFont.Weight.Bold)

        operator_format = QTextCharFormat()
        operator_format.setForeground(QColor("#64B5F6"))  # Azul claro para operadores

        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#FFAB91"))  # Rosa claro para números

        identifier_format = QTextCharFormat()
        identifier_format.setForeground(QColor("#76FF03"))  # Verde lima para identificadores

        # Añadir reglas de resaltado
        keywords = r'\b(entero|decimal|booleano|cadena|si|sino|mientras|hacer|verdadero|falso)\b'
        operators = r'[+\-*/%]|==|!=|<=|>=|<|>|&&|\|\||='
        numbers = r'\b\d+\b'
        identifiers = r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'

        self._highlighting_rules.append((QRegularExpression(keywords), keyword_format))
        self._highlighting_rules.append((QRegularExpression(operators), operator_format))
        self._highlighting_rules.append((QRegularExpression(numbers), number_format))
        self._highlighting_rules.append((QRegularExpression(identifiers), identifier_format))

    def highlightBlock(self, text):
        for pattern, fmt in self._highlighting_rules:
            expression = pattern.globalMatch(text)
            while expression.hasNext():
                match = expression.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), fmt)

class Inicio(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Inicio")
        self.setGeometry(100, 100, 800, 600)  # Establecer tamaño

        # Configuración de la fuente y estilo
        title_font = QFont("Arial", 24, QFont.Weight.Bold)
        subtitle_font = QFont("Arial", 16, QFont.Weight.Normal)

        # Crear widgets
        title_label = QLabel("Analizador Léxico", self)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("color: #FFFFFF;")  # Texto blanco

        subtitle_label = QLabel("Josue Emanuel Barrios Estrada", self)
        subtitle_label.setFont(subtitle_font)
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_label.setStyleSheet("color: #FFFFFF;")  # Texto blanco

        start_button = QPushButton("Iniciar", self)
        start_button.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        start_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px;")
        start_button.clicked.connect(self.start_program)

        # Configuración del layout
        layout = QVBoxLayout()
        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)
        layout.addWidget(start_button)

        container = QWidget()
        container.setLayout(layout)
        container.setStyleSheet("background-color: #121212;")  # Fondo oscuro
        self.setCentralWidget(container)

    def start_program(self):
        self.close()
        self.show_main_window()

    def show_main_window(self):
        self.main_window = AnalizadorLexico()
        self.main_window.show()

class AnalizadorLexico(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Analizador Léxico")
        self.setGeometry(100, 100, 800, 600)  # Establecer tamaño

        self.text_area = QTextEdit(self)
        self.text_area.setReadOnly(False)
        self.text_area.setFont(QFont("Courier", 12))
        self.text_area.setStyleSheet("background-color: #2B2B2B; color: #E0E0E0;")

        self.highlighter = CodigoHighlighter(self.text_area.document())

        self.load_button = QPushButton("Cargar Archivo", self)
        self.load_button.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.load_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px;")
        self.load_button.clicked.connect(self.cargar_archivo)

        self.save_button = QPushButton("Guardar Archivo", self)
        self.save_button.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.save_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px;")
        self.save_button.clicked.connect(self.guardar_archivo)

        self.clear_button = QPushButton("Eliminar Texto", self)
        self.clear_button.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.clear_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px;")
        self.clear_button.clicked.connect(self.eliminar_texto)

        self.analyze_button = QPushButton("Analizar", self)
        self.analyze_button.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        self.analyze_button.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px;")
        self.analyze_button.clicked.connect(self.analizar_lexico)

        self.table_widget = QTableWidget(self)
        self.table_widget.setColumnCount(3)
        self.table_widget.setHorizontalHeaderLabels(["TOKEN", "TIPO", "CANTIDAD"])
        self.table_widget.setFont(QFont("Arial", 12))
        self.table_widget.setStyleSheet("background-color: #333333; color: #E0E0E0; gridline-color: #555555;")
        self.table_widget.horizontalHeader().setStyleSheet("background-color: #4CAF50; color: white;")
        self.table_widget.verticalHeader().setVisible(False)
        self.table_widget.setAlternatingRowColors(True)
        self.table_widget.setStyleSheet("alternate-background-color: #444444; background-color: #333333;")

        layout = QVBoxLayout()
        layout.addWidget(self.load_button)
        layout.addWidget(self.save_button)
        layout.addWidget(self.clear_button)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.text_area)
        layout.addWidget(self.table_widget)

        container = QWidget()
        container.setLayout(layout)
        container.setStyleSheet("background-color: #121212;")  # Fondo oscuro
        self.setCentralWidget(container)

    def cargar_archivo(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Seleccionar Archivo", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            with open(file_name, 'r') as file:
                content = file.read()
                self.text_area.setText(content)

    def guardar_archivo(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Guardar Archivo", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            with open(file_name, 'w') as file:
                content = self.text_area.toPlainText()
                file.write(content)

    def eliminar_texto(self):
        self.text_area.clear()

    def analizar_lexico(self):
        content = self.text_area.toPlainText()
        token_patterns = {
            'Palabra Reservada': re.compile(r'\b(entero|decimal|booleano|cadena|si|sino|mientras|hacer|verdadero|falso)\b'),
            'Operador': re.compile(r'[+\-*/%]|==|!=|<=|>=|<|>|&&|\|\||='),
            'Número': re.compile(r'\b\d+\b'),
            'Identificador': re.compile(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'),
            'Signos': re.compile(r'[{}()\[\];,]')
        }
        token_counts = {}
        error_lines = []

        for line_num, line in enumerate(content.splitlines(), start=1):
            found_tokens = set()
            line_cleaned = re.sub(r'\s+', ' ', line).strip()
            for token_type, regex in token_patterns.items():
                for match in re.finditer(regex, line_cleaned):
                    token = match.group()
                    if token not in found_tokens:
                        found_tokens.add(token)
                        if token in token_counts:
                            token_counts[token]['count'] += 1
                        else:
                            token_counts[token] = {'type': token_type, 'count': 1}
            remaining_chars = re.sub('|'.join(regex.pattern for regex in token_patterns.values()), '', line_cleaned).strip()
            if remaining_chars:
                error_lines.append((line_num, remaining_chars))

        self.table_widget.setRowCount(len(token_counts))
        for row, (token, info) in enumerate(token_counts.items()):
            self.table_widget.setItem(row, 0, QTableWidgetItem(token))
            self.table_widget.setItem(row, 1, QTableWidgetItem(info['type']))
            self.table_widget.setItem(row, 2, QTableWidgetItem(str(info['count'])))

        if error_lines:
            error_message = "Errores léxicos encontrados en las siguientes líneas:\n" + \
                            "\n".join(f"Línea {line}: {error}" for line, error in error_lines)
            QMessageBox.critical(self, "Errores Léxicos", error_message)
        else:
            QMessageBox.information(self, "Análisis Completo", "Análisis léxico completado sin errores.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    inicio = Inicio()
    inicio.show()
    sys.exit(app.exec())
