<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analytic Report</title>
    <link rel="stylesheet" href="<?php echo base_url('assets/css/style.css'); ?>">
</head>
<body>
    <h1>User Activity and Attack Analysis</h1>

    <h2>Detected Malicious Files</h2>
    <table border="1">
        <thead>
            <tr>
                <th>File Path</th>
                <th>Detected Attacks</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($malicious_files as $file): ?>
                <tr>
                    <td><?php echo htmlspecialchars($file[0]); ?></td>
                    <td><?php echo htmlspecialchars(implode(', ', array_slice($file, 1))); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <h2>User Activity</h2>
    <?php if ($user_activity): ?>
        <img src="<?php echo base_url($user_activity); ?>" alt="User Activity Graph">
    <?php else: ?>
        <p>No user activity graph available.</p>
    <?php endif; ?>

    <h2>Detected Attack Distribution</h2>
    <img src="<?php echo base_url('assets/images/attack_distribution.png'); ?>" alt="Attack Distribution Graph">
</body>
</html>
