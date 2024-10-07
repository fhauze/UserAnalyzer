<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Analytic extends CI_Controller {

    public function __construct() {
        parent::__construct();
        // Load model atau library yang diperlukan di sini
    }

    public function index() {
        // Memuat data analisis dari file CSV yang dihasilkan
        $data['malicious_files'] = $this->loadMaliciousFiles();
        $data['user_activity'] = $this->loadUserActivity();
        $this->load->view('analytic_view', $data);
    }

    private function loadMaliciousFiles() {
        // Mengambil data dari file CSV
        $file_path = 'malicious_files_detected.csv';
        if (file_exists($file_path)) {
            return array_map('str_getcsv', file($file_path));
        }
        return [];
    }

    private function loadUserActivity() {
        // Mengambil data dari file grafik aktivitas pengguna
        return file_exists('assets/images/user_activity.png') ? 'assets/images/user_activity.png' : '';
    }
}
