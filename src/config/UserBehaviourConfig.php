<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class UserBehaviourConfig {
    public static function runUserBehaviourDetector() {
        // Menjalankan script Python di background
        $command = 'python ' . APPPATH . '../python/UserBehaviourDetector.py > /dev/null 2>&1 &';
        exec($command);
    }
}
