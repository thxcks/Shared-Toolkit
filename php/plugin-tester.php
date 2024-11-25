<?php
/**
 * WordPress Plugin Tester
 *
 * This PHP tool is designed to help diagnose issues caused by plugins in a WordPress installation.
 * It works by sequentially disabling each active plugin and prompting the user to check if the issue is resolved.
 * 
 * Features:
 * - "Start" button to begin testing plugins, disabling one plugin at a time.
 * - "Next Plugin" button to re-enable the last disabled plugin and disable the next one.
 * - "Fixed" button to stop testing and confirm the last disabled plugin as the source of the issue.
 * - "Reset All Plugins" button to restore all plugins to their enabled state.
 * - Provides clear, styled UI prompts to guide the testing process.
 * 
 * Usage:
 * 1. Place this file in the root directory of your WordPress installation.
 * 2. Access the file through your web browser.
 * 3. Click "Start" to begin the testing process.
 * 4. Use "Next Plugin" and "Fixed" buttons as needed.
 * 5. Click "Reset All Plugins" to re-enable any plugins that were disabled during testing.
 * 
 * Note: This tool temporarily renames plugin folders to disable them. All modifications are reversed 
 * when "Reset All Plugins" is clicked.
 * 
 */
 

// Define the lock file path
$lockFilePath = __DIR__ . '/ip_lock.lock';

// Get the visitor's IP address
$visitorIp = $_SERVER['REMOTE_ADDR'];

// Check if the lock file exists
if (!file_exists($lockFilePath)) {
    // If not, create it and store the current visitor's IP
    file_put_contents($lockFilePath, $visitorIp);
}

// Read the locked IP from the file
$lockedIp = file_get_contents($lockFilePath);

// Check if the current visitor's IP matches the locked IP
if (trim($lockedIp) !== $visitorIp) {
    // Deny access for other IPs
    exit("Access denied. This tool is locked to another IP.");
}

if (isset($_POST['destroy'])) {
    // Get the current file path
    $filePath = __FILE__;
    $lockFilePath = dirname(__FILE__) . '/ip_lock.lock';

    echo "
    <style>
        body { font-family: Arial, sans-serif; background-color: #f7f7f7; padding: 20px; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        #message-container { text-align: center; background-color: #fff; padding: 40px; border-radius: 8px; box-shadow: 0px 0px 8px rgba(0, 0, 0, 0.1); max-width: 400px; }
        .success-icon { font-size: 50px; color: #28a745; margin-bottom: 15px; }
        h2 { color: #333; font-size: 22px; margin: 0; }
        p { color: #666; font-size: 16px; margin-top: 5px; }
    </style>
    <div id='message-container'>";

    // Display success icon and friendly message
    echo "<div class='success-icon'>✓</div>";

    // Delete the ip_lock.lock file
    if (file_exists($lockFilePath) && unlink($lockFilePath)) {
        echo "<h2>Cleanup Successful</h2>";
        echo "<p>The lock file was removed successfully.</p>";
    } else {
        echo "<h2>Cleanup Partial</h2>";
        echo "<p>The lock file was not found or couldn't be removed.</p>";
    }

    // Delete the file itself
    if (unlink($filePath)) {
        echo "<h2>Tool Deleted</h2>";
        echo "<p>This tool has been removed from the system.</p>";
    } else {
        echo "<h2>Deletion Failed</h2>";
        echo "<p>There was an issue deleting this tool.</p>";
    }

    echo "</div>";

    // Stop further execution
    exit;
}

define('WP_USE_THEMES', false);
require('./wp-load.php');

$plugin_dir = WP_CONTENT_DIR . '/plugins/';

// Reset session on page load for fresh start
unset($_SESSION['current_plugin']);

// Handle AJAX request for plugin actions
if (isset($_POST['action'])) {
    $action = $_POST['action'];
    
    if ($action === 'disable_plugin') {
        $plugin = sanitize_text_field($_POST['plugin']);
        $next = sanitize_text_field($_POST['next']);

        if ($next === 'true') {
            // Re-enable previous plugin
            if (is_dir($plugin_dir . $plugin . '_disabled')) {
                rename($plugin_dir . $plugin . '_disabled', $plugin_dir . $plugin);
            }

            // Get the next plugin to disable
            $active_plugins = array_filter(scandir($plugin_dir), function($dir) {
                return is_dir(WP_CONTENT_DIR . '/plugins/' . $dir) && !str_ends_with($dir, '_disabled') && $dir !== '.' && $dir !== '..';
            });
            $active_plugins = array_values($active_plugins);
            $current_index = array_search($_SESSION['current_plugin'], $active_plugins);
            $next_plugin = $active_plugins[$current_index + 1] ?? null;

            if ($next_plugin) {
                rename($plugin_dir . $next_plugin, $plugin_dir . $next_plugin . '_disabled');
                $_SESSION['current_plugin'] = $next_plugin;
                echo json_encode(['next_plugin' => $next_plugin]);
            } else {
                echo json_encode(['message' => 'All plugins tested.']);
            }
        } elseif ($next === 'start') {
            // Starting with the first plugin
            $first_plugin = sanitize_text_field($_POST['plugin']);
            rename($plugin_dir . $first_plugin, $plugin_dir . $first_plugin . '_disabled');
            $_SESSION['current_plugin'] = $first_plugin;
            echo json_encode(['message' => "$first_plugin is disabled, please test."]);
        } else {
            echo json_encode(['message' => "Plugin $plugin was at fault and remains disabled."]);
        }
    } elseif ($action === 'reset_plugins') {
        // Reset all plugins by removing "_disabled" suffix
        foreach (scandir($plugin_dir) as $plugin) {
            if (str_ends_with($plugin, '_disabled') && is_dir($plugin_dir . $plugin)) {
                rename($plugin_dir . $plugin, $plugin_dir . str_replace('_disabled', '', $plugin));
            }
        }
        echo json_encode(['message' => 'All plugins have been reset.']);
    }
    exit;
}

// Retrieve all active plugins initially
$active_plugins = array_filter(scandir($plugin_dir), function($dir) {
    return is_dir(WP_CONTENT_DIR . '/plugins/' . $dir) && !str_ends_with($dir, '_disabled') && $dir !== '.' && $dir !== '..';
});
$active_plugins = array_values($active_plugins);
$first_plugin = $active_plugins[0] ?? null;

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WordPress Plugin Tester</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f7f7f7; text-align: center; }
        #container { max-width: 400px; margin: 50px auto; padding: 20px; background: #fff; border-radius: 10px; box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1); }
        h2 { font-size: 24px; color: #333; }
        .description { font-size: 16px; color: #555; margin-top: 10px; margin-bottom: 20px; }
        #message { font-size: 18px; margin: 20px 0; color: #333; }
        button { padding: 10px 20px; font-size: 16px; margin: 5px; cursor: pointer; border: none; border-radius: 5px; }
        #start { background-color: #28a745; color: #fff; }
        #next-plugin { background-color: #007bff; color: #fff; display: none; }
        #fixed { background-color: #dc3545; color: #fff; display: none; }
        #reset { background-color: #ffc107; color: #fff; }
        button:disabled { background-color: #ccc; }
    </style>
</head>
<body>
    <div id="container">
        <h2>WordPress Plugin Tester</h2>
        <p class="description">This tool helps identify the plugin causing issues on your site. Plugins will be disabled one at a time for testing. Click "Next Plugin" if the issue persists, or "Fixed" if you've identified the problematic plugin.</p>
        <div id="message">
            <p>Click "Start" to begin testing plugins.</p>
        </div>
        <button id="start">Start</button>
        <button id="next-plugin" disabled>Next Plugin</button>
        <button id="fixed" disabled>Fixed</button>
        <button id="reset">Reset All Plugins</button>
    </div>

 <center>        
    <form method="post">
    <button type="submit" name="destroy" onclick="return confirm('Are you sure? This action is irreversible.')">
        Finished? Destroy tool now
    </button>
    </form>
</center>

    <script>
        let currentPlugin = "<?php echo $first_plugin; ?>"; // First plugin to start with

        function startTesting() {
            $.ajax({
                type: 'POST',
                url: '', // Current file
                data: { action: 'disable_plugin', plugin: currentPlugin, next: 'start' },
                dataType: 'json',
                success: function(response) {
                    $('#message').html("<p>" + response.message + "</p>");
                    $('#start').hide();
                    $('#next-plugin').show().prop('disabled', false);
                    $('#fixed').show().prop('disabled', false);
                }
            });
        }

        function disableNextPlugin() {
            $.ajax({
                type: 'POST',
                url: '', // Current file
                data: { action: 'disable_plugin', plugin: currentPlugin, next: 'true' },
                dataType: 'json',
                success: function(response) {
                    if (response.next_plugin) {
                        currentPlugin = response.next_plugin;
                        $('#message').html("<p>" + currentPlugin + " is disabled, please test.</p>");
                    } else {
                        $('#message').html("<p>All plugins tested.</p>");
                        $('#next-plugin').hide();
                    }
                }
            });
        }

        function resetPlugins() {
            $.post('', { action: 'reset_plugins' }, function(response) {
                $('#message').html("<p>" + response.message + "</p>");
                $('#start').show();
                $('#next-plugin').hide();
                $('#fixed').hide();
            }, 'json');
        }

        $('#start').click(function() {
            startTesting();
        });

        $('#next-plugin').click(function() {
            disableNextPlugin();
        });

        $('#fixed').click(function() {
            $.post('', { action: 'disable_plugin', plugin: currentPlugin, next: 'false' }, function(response) {
                $('#message').html("<p>" + response.message + "</p>");
                $('#next-plugin').hide();
                $('#fixed').hide();
            }, 'json');
        });

        $('#reset').click(function() {
            resetPlugins();
        });
    </script>
</body>
</html>
