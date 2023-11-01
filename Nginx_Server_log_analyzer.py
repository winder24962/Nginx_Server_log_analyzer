import sys
import re
import matplotlib.pyplot as plt
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget, QLabel, QFileDialog, QTableWidget, QTableWidgetItem, QTabWidget
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

class LogAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Access Log Analyzer")
        self.setGeometry(100, 100, 800, 600)

        self.central_widget = QTabWidget(self)
        self.setCentralWidget(self.central_widget)

        self.main_tab = QWidget(self)
        self.monitoring_tab = QWidget(self)
        self.graph_tab = QWidget(self)

        self.central_widget.addTab(self.main_tab, "Main")
        self.central_widget.addTab(self.monitoring_tab, "Monitoring")
        self.central_widget.addTab(self.graph_tab, "Graph")

        self.log_text = QTextEdit(self.main_tab)
        self.log_text.setPlaceholderText("Select an access.log file")

        self.browse_button = QPushButton("Browse", self.main_tab)
        self.browse_button.clicked.connect(self.open_file_dialog)

        self.analyze_button = QPushButton("Analyze", self.main_tab)
        self.analyze_button.clicked.connect(self.analyze_log)

        self.clear_data_button = QPushButton("Clear Data", self.main_tab)
        self.clear_data_button.clicked.connect(self.clear_data)

        self.attribute_label = QLabel(self.main_tab)
        self.attribute_label.setText("Attributes")

        self.attribute_table = QTableWidget(self.main_tab)
        self.attribute_table.setColumnCount(2)
        self.attribute_table.setHorizontalHeaderLabels(["Attribute", "Values"])
        self.attribute_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.attributes_to_display = ["time_local", "remote_addr", "request", "status", "body_bytes_sent", "request_time", "http_referer", "http_user_agent"]
        self.attributes = {}

        self.abnormal_logs_label = QLabel(self.main_tab)
        self.abnormal_logs_label.setText("Abnormal Logs")

        self.abnormal_logs_text = QTextEdit(self.main_tab)
        self.abnormal_logs_text.setReadOnly(True)

        self.status_label = QLabel(self.monitoring_tab)
        self.status_label.setText("Status")

        self.status_table = QTableWidget(self.monitoring_tab)
        self.status_table.setColumnCount(2)
        self.status_table.setHorizontalHeaderLabels(["Status Code", "Count"])
        self.status_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.remote_addr_label = QLabel(self.monitoring_tab)
        self.remote_addr_label.setText("Remote Address")

        self.remote_addr_table = QTableWidget(self.monitoring_tab)
        self.remote_addr_table.setColumnCount(2)
        self.remote_addr_table.setHorizontalHeaderLabels(["Remote Address", "Count"])
        self.remote_addr_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.request_values_label = QLabel(self.monitoring_tab)
        self.request_values_label.setText("Request Values")

        self.request_values_table = QTableWidget(self.monitoring_tab)
        self.request_values_table.setColumnCount(2)
        self.request_values_table.setHorizontalHeaderLabels(["Request", "Count"])
        self.request_values_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.access_count_label = QLabel(self.monitoring_tab)
        self.access_count_label.setText("Access Count by Hour")

        self.access_count_table = QTableWidget(self.monitoring_tab)
        self.access_count_table.setColumnCount(2)
        self.access_count_table.setHorizontalHeaderLabels(["Hour", "Count"])
        self.access_count_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.http_referer_label = QLabel(self.monitoring_tab)
        self.http_referer_label.setText("HTTP Referer")

        self.http_referer_table = QTableWidget(self.monitoring_tab)
        self.http_referer_table.setColumnCount(2)
        self.http_referer_table.setHorizontalHeaderLabels(["HTTP Referer", "Count"])
        self.http_referer_table.setEditTriggers(QTableWidget.NoEditTriggers)

        self.histogram_label = QLabel(self.graph_tab)
        self.histogram_label.setText("Request Time and Body Bytes Sent Distribution")

        self.histogram_canvas = plt.figure(figsize=(8, 6))
        self.histogram_canvas_widget = FigureCanvas(self.histogram_canvas)
        self.histogram_layout = QVBoxLayout(self.graph_tab)
        self.histogram_layout.addWidget(self.histogram_label)
        self.histogram_layout.addWidget(self.histogram_canvas_widget)

        layout_main = QVBoxLayout(self.main_tab)
        layout_main.addWidget(self.log_text)
        layout_main.addWidget(self.browse_button)
        layout_main.addWidget(self.analyze_button)
        layout_main.addWidget(self.clear_data_button)
        layout_main.addWidget(self.attribute_label)
        layout_main.addWidget(self.attribute_table)
        layout_main.addWidget(self.abnormal_logs_label)
        layout_main.addWidget(self.abnormal_logs_text)

        layout_monitoring = QVBoxLayout(self.monitoring_tab)
        layout_monitoring.addWidget(self.status_label)
        layout_monitoring.addWidget(self.status_table)
        layout_monitoring.addWidget(self.remote_addr_label)
        layout_monitoring.addWidget(self.remote_addr_table)
        layout_monitoring.addWidget(self.request_values_label)
        layout_monitoring.addWidget(self.request_values_table)
        layout_monitoring.addWidget(self.access_count_label)
        layout_monitoring.addWidget(self.access_count_table)
        layout_monitoring.addWidget(self.http_referer_label)
        layout_monitoring.addWidget(self.http_referer_table)

        self.selected_file_path = None
        self.remote_addr_counts = {}

        self.result_text = QTextEdit(self.monitoring_tab)
        self.result_text.setReadOnly(True)
        self.result_text.hide()

    def open_file_dialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_dialog = QFileDialog()
        file_dialog.setOptions(options)
        file_path, _ = file_dialog.getOpenFileName(self, "Open access.log file", "", "Log Files (*.log)")
        if file_path:
            self.selected_file_path = file_path
            self.log_text.setText(file_path)

    def analyze_log(self):
        self.clear_display_data()

        if self.selected_file_path:
            log_file_path = self.selected_file_path
            try:
                with open(log_file_path, 'r', encoding='utf-8') as log_file:
                    log_content = log_file.read()
                lines = log_content.split("\n")
            except FileNotFoundError:
                self.display_result("Log file not found.")
                return

            time_local_data = {}
            request_values = {}
            abnormal_logs = []
            status_counts = {}
            request_times = []
            body_bytes_sents = []

            for line in lines:
                if not line.strip():  # Skip empty lines
                    continue

                match = re.search(r'"status":"(\d+)"', line)
                if match:
                    status_code = int(match.group(1))
                    status_counts[status_code] = status_counts.get(status_code, 0) + 1

                attribute_matches = re.findall(r'"(\w+)":"([^"]*)"', line)
                for attribute, value in attribute_matches:
                    if attribute == 'http_user_agent':
                        continue
                    if attribute not in self.attributes:
                        self.attributes[attribute] = set()
                    self.attributes[attribute].add(value)

                    if attribute == 'request':
                        request_values[value] = request_values.get(value, 0) + 1

                    if attribute == 'http_user_agent' and "Nikto" in value:
                        abnormal_logs.append(line)

                    if attribute == 'request_time':
                        request_time = float(value)
                        request_times.append(request_time)

                    if attribute == 'body_bytes_sent':
                        body_bytes_sent = int(value)
                        body_bytes_sents.append(body_bytes_sent)

                remote_addr_match = re.search(r'"remote_addr":"([^"]*)"', line)
                if remote_addr_match:
                    remote_addr = remote_addr_match.group(1)
                    if remote_addr:
                        if remote_addr in self.remote_addr_counts:
                            self.remote_addr_counts[remote_addr] += 1
                        else:
                            self.remote_addr_counts[remote_addr] = 1

                time_local_match = re.search(r'"time_local":"([^"]*)"', line)
                if time_local_match:
                    time_local = time_local_match.group(1)
                    hour = time_local.split(':')[1]
                    if hour in time_local_data:
                        time_local_data[hour] += 1
                    else:
                        time_local_data[hour] = 1

                if self.is_abnormal_log(line):
                    abnormal_logs.append(line)

            self.display_attributes()
            self.display_remote_addr_counts()
            self.display_request_values(request_values)
            self.display_access_count_by_hour(time_local_data)
            self.display_http_referer_counts(lines)
            self.display_status_counts(status_counts)
            self.display_histograms(request_times, body_bytes_sents)

            if abnormal_logs:
                self.abnormal_logs_text.setPlainText("\n".join(abnormal_logs))
            else:
                self.abnormal_logs_text.setPlainText("No abnormal logs found.")
        else:
            self.display_result("Please select a log file.")

    def display_histograms(self, request_times, body_bytes_sents):
        if request_times or body_bytes_sents:
            plt.figure(self.histogram_canvas.number)
            plt.clf()

        if request_times:
            ax1 = self.histogram_canvas.add_subplot(2, 1, 1)
            ax1.hist(request_times, bins=20, alpha=0.5, color='blue', label='Request Time')
            ax1.set_xlabel('Request Time (s)')
            ax1.set_ylabel('Frequency')
            ax1.set_title('Request Time Distribution')
            ax1.legend()

        if body_bytes_sents:
            ax2 = self.histogram_canvas.add_subplot(2, 1, 2)
            ax2.hist(body_bytes_sents, bins=20, alpha=0.5, color='green', label='Body Bytes Sent')
            ax2.set_xlabel('Body Bytes Sent')
            ax2.set_ylabel('Frequency')
            ax2.set_title('Body Bytes Sent Distribution')
            ax2.legend()

        self.histogram_canvas_widget.draw()

    def display_result(self, text):
        self.result_text.setPlainText(text)

    def clear_display_data(self):
        self.display_result("")
        self.attribute_table.setRowCount(0)
        self.remote_addr_table.setRowCount(0)
        self.request_values_table.setRowCount(0)
        self.access_count_table.setRowCount(0)
        self.status_table.setRowCount(0)
        self.abnormal_logs_text.clear()
        self.http_referer_table.setRowCount(0)

        self.attributes.clear()
        self.remote_addr_counts.clear()

    def display_attributes(self):
        if self.selected_file_path:
            try:
                with open(self.selected_file_path, 'r', encoding='utf-8') as log_file:
                    log_content = log_file.read()
                lines = log_content.split("\n")
            except FileNotFoundError:
                self.display_result("Log file not found.")
                return

            self.attribute_table.setRowCount(len(self.attributes_to_display))
            row = 0
            for attribute in self.attributes_to_display:
                if attribute in self.attributes:
                    values = ", ".join(self.get_top_attribute_values(attribute, 3, lines))
                    self.attribute_table.setItem(row, 0, QTableWidgetItem(attribute))
                    self.attribute_table.setItem(row, 1, QTableWidgetItem(values))
                    row += 1
        else:
            self.display_result("Please select a log file.")

    def get_top_attribute_values(self, attribute, num_values, lines):
        if attribute in self.attributes:
            values = list(self.attributes[attribute])
            value_counts = {value: 0 for value in values}
            for line in lines:
                attribute_matches = re.findall(r'"(\w+)":"([^"]*)"', line)
                for attr, value in attribute_matches:
                    if attr == attribute:
                        value_counts[value] += 1
            top_values = sorted(value_counts, key=lambda x: value_counts[x], reverse=True)[:num_values]
            return top_values
        return []

    def display_remote_addr_counts(self):
        self.remote_addr_table.setRowCount(len(self.remote_addr_counts))
        row = 0
        for remote_addr, count in sorted(self.remote_addr_counts.items(), key=lambda x: x[1], reverse=True):
            self.remote_addr_table.insertRow(row)
            self.remote_addr_table.setItem(row, 0, QTableWidgetItem(remote_addr))
            self.remote_addr_table.setItem(row, 1, QTableWidgetItem(str(count)))
            row += 1

    def display_request_values(self, values):
        if values:
            self.request_values_table.setRowCount(len(values))
            row = 0
            for request, count in values.items():
                self.request_values_table.setItem(row, 0, QTableWidgetItem(request))
                self.request_values_table.setItem(row, 1, QTableWidgetItem(str(count)))
                row += 1

    def display_access_count_by_hour(self, data):
        if data:
            self.access_count_table.setRowCount(len(data))
            row = 0
            for hour, count in sorted(data.items()):
                self.access_count_table.setItem(row, 0, QTableWidgetItem(hour))
                self.access_count_table.setItem(row, 1, QTableWidgetItem(str(count)))
                row += 1

    def display_http_referer_counts(self, lines):
        http_referers = {}
        for line in lines:
            match = re.search(r'"http_referer":"([^"]*)"', line)
            if match:
                referer = match.group(1)
                if referer:
                    http_referers[referer] = http_referers.get(referer, 0) + 1
        self.http_referer_table.setRowCount(len(http_referers))
        row = 0
        for referer, count in sorted(http_referers.items(), key=lambda x: x[1], reverse=True):
            self.http_referer_table.insertRow(row)
            self.http_referer_table.setItem(row, 0, QTableWidgetItem(referer))
            self.http_referer_table.setItem(row, 1, QTableWidgetItem(str(count)))
            row += 1

    def display_status_counts(self, status_counts):
        self.status_table.setRowCount(len(status_counts))
        row = 0
        for status, count in sorted(status_counts.items(), key=lambda x: x[0]):
            self.status_table.setItem(row, 0, QTableWidgetItem(str(status)))
            self.status_table.setItem(row, 1, QTableWidgetItem(str(count)))
            row += 1

    def is_abnormal_log(self, line):
        match1 = re.search(r'"body_bytes_sent":"(\d+)"', line)
        match2 = re.search(r'"request_time":"([\d.]+)"', line)
        if match1 and match2:
            body_bytes_sent = int(match1.group(1))
            request_time = float(match2.group(1))
            return body_bytes_sent > 1000000 or request_time > 10.0 or "Nikto" in line
        return False

    def clear_data(self):
        self.clear_display_data()
        plt.figure(self.histogram_canvas.number)
        plt.clf()

def main():
    app = QApplication(sys.argv)
    window = LogAnalyzer()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
