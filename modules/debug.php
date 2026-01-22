<?php
/**
 * Module Debug Info - VULNÉRABLE À LA DIVULGATION D'INFORMATIONS
 * 
 * 🎯 OBJECTIF : Trouver le flag caché dans les headers HTTP
 */

// CORRECTION : Supprimer les headers de debug sensibles
// Pas de header 'X-Debug-Flag' ni 'X-Server-Mode' en production
// On masque aussi la version de PHP
// header('X-Powered-By: PHP/' . PHP_VERSION); // SUPPRIMÉ
// header('X-Server-Mode: development'); // SUPPRIMÉ

// Informations serveur
$serverInfo = [
    'PHP Version' => PHP_VERSION,
    'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'N/A',
    'Document Root' => $_SERVER['DOCUMENT_ROOT'] ?? 'N/A',
    'Script Filename' => $_SERVER['SCRIPT_FILENAME'] ?? 'N/A',
    'Server Admin' => $_SERVER['SERVER_ADMIN'] ?? 'webmaster@localhost',
    'Server Protocol' => $_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1',
    'Request Method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'Request URI' => $_SERVER['REQUEST_URI'] ?? '/',
];

// Informations PHP
$phpInfo = [
    'PHP SAPI' => php_sapi_name(),
    'Zend Version' => zend_version(),
    'Memory Limit' => ini_get('memory_limit'),
    'Max Execution Time' => ini_get('max_execution_time') . 's',
    'Upload Max Filesize' => ini_get('upload_max_filesize'),
    'Post Max Size' => ini_get('post_max_size'),
    'Display Errors' => ini_get('display_errors') ? 'ON' : 'OFF',
    'Error Reporting' => error_reporting(),
    'Session Save Path' => ini_get('session.save_path') ?: '(default)',
    'Timezone' => date_default_timezone_get(),
];

// Extensions chargées (groupées)
$extensions = get_loaded_extensions();
sort($extensions);
?>

<div class="container">
    <div class="module-card">
        <div class="module-header">
            <h1>🐛 Debug Info</h1>
            <span class="badge badge-info">Info Disclosure</span>
        </div>
        
        <div class="module-hint">
            <h3>💡 Objectif</h3>
            <p>Il semblerait que ce site affiche des données sensibles à propos du serveur...</p>
            <p>Peut-être qu'en fouillant on trouvera quelque chose d'utile.</p>
        </div>
        
        <div class="debug-section">
            <h3>🖥️ Informations Serveur</h3>
            <table class="debug-table">
                <thead>
                    <tr>
                        <th>Clé</th>
                        <th>Valeur</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($serverInfo as $key => $value): ?>
                        <tr>
                            <td><?= htmlspecialchars($key) ?></td>
                            <td><code><?= htmlspecialchars($value) ?></code></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        
        <div class="debug-section">
            <h3>🔧 Configuration PHP</h3>
            <table class="debug-table">
                <thead>
                    <tr>
                        <th>Paramètre</th>
                        <th>Valeur</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($phpInfo as $key => $value): ?>
                        <tr>
                            <td><?= htmlspecialchars($key) ?></td>
                            <td><code><?= htmlspecialchars((string)$value) ?></code></td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        
        <div class="debug-section">
            <h3>📦 Extensions PHP chargées (<?= count($extensions) ?>)</h3>
            <div class="extensions-grid">
                <?php foreach ($extensions as $ext): ?>
                    <span class="extension-badge"><?= htmlspecialchars($ext) ?></span>
                <?php endforeach; ?>
            </div>
        </div>
        
        <div class="debug-section">
            <h3>🌐 Variables $_SERVER</h3>
            <table class="debug-table">
                <thead>
                    <tr>
                        <th>Variable</th>
                        <th>Valeur</th>
                    </tr>
                </thead>
                <tbody>
                    <?php 
                    $serverVars = ['HTTP_HOST', 'HTTP_USER_AGENT', 'HTTP_ACCEPT', 'HTTP_ACCEPT_LANGUAGE', 'REMOTE_ADDR', 'REMOTE_PORT'];
                    foreach ($serverVars as $var): 
                        if (isset($_SERVER[$var])):
                    ?>
                        <tr>
                            <td><?= htmlspecialchars($var) ?></td>
                            <td><code><?= htmlspecialchars(substr($_SERVER[$var], 0, 100)) ?></code></td>
                        </tr>
                    <?php 
                        endif;
                    endforeach; 
                    ?>
                </tbody>
            </table>
        </div>
        
        <div class="debug-section">
            <h3>⏰ Informations Date/Heure</h3>
            <table class="debug-table">
                <tr><td>Date Serveur</td><td><code><?= date('Y-m-d H:i:s') ?></code></td></tr>
                <tr><td>Timestamp Unix</td><td><code><?= time() ?></code></td></tr>
                <tr><td>Timezone</td><td><code><?= date_default_timezone_get() ?></code></td></tr>
            </table>
        </div>
    </div>
</div>
