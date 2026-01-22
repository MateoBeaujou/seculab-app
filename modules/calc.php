<?php
/**
 * Module Calc-Express - VULNÉRABLE AU RCE (Remote Code Execution)
 * 
 * 🎯 OBJECTIF : Exécuter du code PHP arbitraire sur le serveur
 * 
 * 💡 INDICE : La fonction eval() exécute du code PHP...
 *    Et si on injectait autre chose qu'un calcul ?
 */

$result = null;
$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['expression'])) {
    $expression = $_POST['expression'];
    
    // CORRECTION : Utiliser un parser mathématique sécurisé
    // On accepte uniquement les chiffres et opérateurs mathématiques
    try {
        // Validation stricte : accepter seulement les nombres, opérateurs et espaces
        if (!preg_match('/^[0-9+\-*\/().\s]+$/', $expression)) {
            $error = "Expression invalide. Utilisez uniquement les chiffres et opérateurs : +, -, *, /, ()";
        } else {
            // Utiliser une solution sécurisée : évaluer avec une libraire ou logique customisée
            // Solution simple : utiliser une function eval alternative
            // Ici on utilise eval avec strict validation
            $result = @eval("return " . $expression . ";");
            
            if ($result === false && !is_numeric($result) && $result !== 0) {
                $error = "Expression invalide ou erreur d'exécution.";
            }
        }
    } catch (Throwable $e) {
        $error = "Erreur : " . $e->getMessage();
    }
}
?>

<div class="container">
    <div class="module-card">
        <div class="module-header">
            <h1>🧮 Calc-Express</h1>
            <span class="badge badge-critical">RCE</span>
        </div>
        
        <div class="module-hint">
            <h3>💡 Objectif</h3>
            <p>Cette calculatrice utilise <code>eval()</code> pour évaluer les expressions...</p>
            <p>Votre mission : Lire le contenu du fichier <code>secret_rce.txt</code> sur le serveur.</p>
        </div>
        
        <?php if ($error): ?>
            <div class="alert alert-danger"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>
        
        <form method="POST" class="calc-form">
            <div class="form-group">
                <label for="expression">Expression mathématique</label>
                <input type="text" id="expression" name="expression" class="form-control" 
                       placeholder="Ex: 2 + 2 * 3" 
                       value="<?= htmlspecialchars($_POST['expression'] ?? '') ?>">
            </div>
            <button type="submit" class="btn btn-primary">Calculer</button>
        </form>
        
        <?php if ($result !== null && !$error): ?>
            <div class="result-box">
                <h3>Résultat :</h3>
                <div class="result-value">
                    <?php 
                    if (is_string($result) && strlen($result) > 100) {
                        echo '<pre>' . htmlspecialchars($result) . '</pre>';
                    } else {
                        echo htmlspecialchars(var_export($result, true));
                    }
                    ?>
                </div>
            </div>
        <?php endif; ?>
        
        <div class="warning-box">
            <h4>⚠️ Note de sécurité</h4>
            <p>Dans un vrai système, n'utilisez <strong>JAMAIS</strong> <code>eval()</code> sur des données utilisateur !</p>
            <p>Préférez une bibliothèque de parsing mathématique sécurisée.</p>
        </div>
    </div>
</div>
