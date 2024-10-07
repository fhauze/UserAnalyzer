<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class UserRequestLogger {
    public function logRequest() {
        $CI =& get_instance();
        $log_data = array(
            'ip_address' => $CI->input->ip_address(),
            'url' => current_url(),
            'request_type' => $CI->input->method(),
            'response_code' => http_response_code(),
            'user_agent' => $CI->input->user_agent(),
            'timestamp' => date('Y-m-d H:i:s'),
        );

        // Simpan data log ke dalam file atau database
        $this->saveLog($log_data);
    }

    private function saveLog($log_data) {
        // Menyimpan data ke file CSV
        $file_path = APPPATH . '../user_logs.csv';

        $fp = fopen($file_path, 'a');
        fputcsv($fp, $log_data);
        fclose($fp);
    }
}