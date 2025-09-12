package ghidragpt.ui;

import ghidragpt.service.GPTService;
import ghidragpt.config.ConfigurationManager;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.ExecutionException;

/**
 * Configuration panel for API settings
 */
public class ConfigurationPanel extends JPanel {
    
    private final GPTService gptService;
    private final ConfigurationManager configManager;
    private final JTextField apiKeyField;
    private final JComboBox<GPTService.GPTProvider> providerCombo;
    private final JTextField modelField;
    private final JSpinner maxTokensSpinner;
    private final JSpinner temperatureSpinner;
    private final JSpinner timeoutSpinner;
    private final JButton testButton;
    private final JLabel statusLabel;
    
    public ConfigurationPanel(GPTService gptService) {
        this.gptService = gptService;
        this.configManager = new ConfigurationManager();
        
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // API Provider
        gbc.gridx = 0; gbc.gridy = 0;
        add(new JLabel("API Provider:"), gbc);
        
        providerCombo = new JComboBox<>(GPTService.GPTProvider.values());
        providerCombo.addActionListener(e -> updateModelField());
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(providerCombo, gbc);
        
        // API Key
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("API Key:"), gbc);
        
        apiKeyField = new JPasswordField(30);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(apiKeyField, gbc);
        
        // Model
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("Model:"), gbc);
        
        modelField = new JTextField("gpt-4", 30);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(modelField, gbc);
        
        // Max Tokens
        gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("Max Tokens:"), gbc);
        
        maxTokensSpinner = new JSpinner(new SpinnerNumberModel(GPTService.DEFAULT_MAX_TOKENS, 100, 32000, 100));
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(maxTokensSpinner, gbc);
        
        // Temperature
        gbc.gridx = 0; gbc.gridy = 4; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("Temperature:"), gbc);
        
        temperatureSpinner = new JSpinner(new SpinnerNumberModel(GPTService.DEFAULT_TEMPERATURE, 0.0, 2.0, 0.1));
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(temperatureSpinner, gbc);
        
        // Timeout
        gbc.gridx = 0; gbc.gridy = 5; gbc.fill = GridBagConstraints.NONE;
        add(new JLabel("Timeout (seconds):"), gbc);
        
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(GPTService.DEFAULT_TIMEOUT_SECONDS, 5, 300, 5));
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL;
        add(timeoutSpinner, gbc);
        
        // Create button panel to center buttons horizontally
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        
        testButton = new JButton("Test Connection");
        testButton.addActionListener(e -> testConnection());
        testButton.setPreferredSize(new Dimension(150, 30));
        buttonPanel.add(testButton);
        
        JButton saveButton = new JButton("Save Configuration");
        saveButton.addActionListener(e -> saveConfiguration());
        saveButton.setPreferredSize(new Dimension(150, 30));
        buttonPanel.add(saveButton);
        
        // Add centered button panel
        gbc.gridx = 0; gbc.gridy = 6; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(5, 5, 5, 5);
        add(buttonPanel, gbc);
        
        // Status label
        statusLabel = new JLabel("Not configured");
        statusLabel.setForeground(Color.RED);
        gbc.gridx = 0; gbc.gridy = 7; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.insets = new Insets(5, 5, 5, 5); // Reset margins
        gbc.weighty = 0.0; // No vertical expansion for status
        add(statusLabel, gbc);
        
        // Vertical spacer to push everything to the top when panel height increases
        JPanel spacer = new JPanel();
        spacer.setOpaque(false);
        gbc.gridx = 0; gbc.gridy = 8; gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0; // Take up all extra vertical space
        gbc.weightx = 1.0; // Take up all extra horizontal space
        add(spacer, gbc);
        
        updateModelField();
        
        // Load configuration from file
        loadConfiguration();
    }
    
    /**
     * Loads configuration from the configuration manager and updates UI
     */
    private void loadConfiguration() {
        // Load saved values
        providerCombo.setSelectedItem(configManager.getProvider());
        apiKeyField.setText(configManager.getApiKey());
        modelField.setText(configManager.getModel());
        maxTokensSpinner.setValue(configManager.getMaxTokens());
        temperatureSpinner.setValue(configManager.getTemperature());
        timeoutSpinner.setValue(configManager.getTimeoutSeconds());
        
        // Update status
        if (configManager.isConfigured()) {
            statusLabel.setText("Configuration loaded");
            statusLabel.setForeground(Color.BLUE);
            
            // Apply to GPT service
            gptService.setApiKey(configManager.getApiKey());
            gptService.setProvider(configManager.getProvider());
            gptService.setModel(configManager.getModel());
            gptService.setMaxTokens(configManager.getMaxTokens());
            gptService.setTemperature(configManager.getTemperature());
            gptService.setTimeoutSeconds(configManager.getTimeoutSeconds());
        } else {
            statusLabel.setText("Configuration incomplete");
            statusLabel.setForeground(Color.ORANGE);
        }
    }
    
    private void updateModelField() {
        GPTService.GPTProvider provider = (GPTService.GPTProvider) providerCombo.getSelectedItem();
        
        // Reset all configuration fields when provider changes
        resetConfigurationFields();
        
        // Set provider-specific defaults
        if (provider == GPTService.GPTProvider.OLLAMA) {
            modelField.setText("llama3.2");
            apiKeyField.setEnabled(false);  // Ollama doesn't require API key
            apiKeyField.setText("Not required for Ollama (local)");
        } else {
            // For all other providers, enable API key field and clear placeholder
            apiKeyField.setEnabled(true);
            if (apiKeyField.getText().equals("Not required for Ollama (local)")) {
                apiKeyField.setText("");
            }
            
            if (provider == GPTService.GPTProvider.OPENAI) {
                modelField.setText("gpt-4o");
            } else if (provider == GPTService.GPTProvider.ANTHROPIC) {
                modelField.setText("claude-sonnet-4-20250514");
            } else if (provider == GPTService.GPTProvider.GEMINI) {
                modelField.setText("gemini-2.5-flash");
            } else if (provider == GPTService.GPTProvider.COHERE) {
                modelField.setText("command");
            } else if (provider == GPTService.GPTProvider.MISTRAL) {
                modelField.setText("mistral-large-latest");
            } else if (provider == GPTService.GPTProvider.DEEPSEEK) {
                modelField.setText("deepseek-chat");
            } else if (provider == GPTService.GPTProvider.GROK) {
                modelField.setText("grok-3");
            }
        }
        
        // Reset status to unconfigured state
        statusLabel.setText("Configuration updated - please test connection");
        statusLabel.setForeground(Color.ORANGE);
    }
    
    private void resetConfigurationFields() {
        // Clear API key field
        apiKeyField.setText("");
        
        // Reset status
        statusLabel.setText("Not configured");
        statusLabel.setForeground(Color.RED);
        
        // Enable API key field by default
        apiKeyField.setEnabled(true);
    }    private void saveConfiguration() {
        String apiKey = apiKeyField.getText().trim();
        GPTService.GPTProvider selectedProvider = (GPTService.GPTProvider) providerCombo.getSelectedItem();
        
        // All providers require API key except Ollama
        if (selectedProvider != GPTService.GPTProvider.OLLAMA && apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an API key", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // For Ollama, clear any placeholder text from API key field
        if (selectedProvider == GPTService.GPTProvider.OLLAMA) {
            apiKey = "";  // Don't save placeholder text
        }
        
        // Save to configuration manager
        configManager.setApiKey(apiKey);
        configManager.setProvider(selectedProvider);
        configManager.setModel(modelField.getText().trim());
        configManager.setMaxTokens((Integer) maxTokensSpinner.getValue());
        configManager.setTemperature((Double) temperatureSpinner.getValue());
        configManager.setTimeoutSeconds((Integer) timeoutSpinner.getValue());
        configManager.saveConfiguration();
        
        // Apply to GPT service
        gptService.setApiKey(apiKey);
        gptService.setProvider(selectedProvider);
        gptService.setModel(modelField.getText().trim());
        gptService.setMaxTokens((Integer) maxTokensSpinner.getValue());
        gptService.setTemperature((Double) temperatureSpinner.getValue());
        gptService.setTimeoutSeconds((Integer) timeoutSpinner.getValue());
        
        statusLabel.setText("Configuration saved");
        statusLabel.setForeground(Color.BLUE);
        
        JOptionPane.showMessageDialog(this, 
            "Configuration saved successfully!\nSaved to: " + configManager.getConfigurationPath(), 
            "Success", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void testConnection() {
        // First update the GPTService with current UI values
        String apiKey = apiKeyField.getText().trim();
        GPTService.GPTProvider selectedProvider = (GPTService.GPTProvider) providerCombo.getSelectedItem();
        String model = modelField.getText().trim();
        
        // Validate inputs before testing
        if (apiKey.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter an API key", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        if (model.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please enter a model name", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        // Apply current UI values to GPTService for testing
        gptService.setApiKey(apiKey);
        gptService.setProvider(selectedProvider);
        gptService.setModel(model);

        testButton.setEnabled(false);
        testButton.setText("Testing...");
        
        // Test in background thread
        SwingWorker<String, Void> worker = new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                return gptService.sendRequest("Hello, this is a test message. Please respond with 'Connection successful'.");
            }
            
            @Override
            protected void done() {
                try {
                    String response = get();
                    if (response.toLowerCase().contains("successful") || response.toLowerCase().contains("hello")) {
                        statusLabel.setText("Connection successful");
                        statusLabel.setForeground(Color.GREEN);
                        
                        // Show success message and prompt to save
                        int result = JOptionPane.showConfirmDialog(ConfigurationPanel.this, 
                            "Connection test successful!\n\nWould you like to save this configuration?", 
                            "Success", JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE);
                        
                        if (result == JOptionPane.YES_OPTION) {
                            saveConfiguration();
                        }
                    } else {
                        statusLabel.setText("Connection test completed");
                        statusLabel.setForeground(Color.BLUE);
                        JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                            "Connection established but unexpected response:\n" + response, 
                            "Warning", JOptionPane.WARNING_MESSAGE);
                    }
                } catch (Exception e) {
                    statusLabel.setText("Connection failed");
                    statusLabel.setForeground(Color.RED);
                    JOptionPane.showMessageDialog(ConfigurationPanel.this, 
                        "Connection test failed:\n" + e.getMessage(), 
                        "Error", JOptionPane.ERROR_MESSAGE);
                } finally {
                    testButton.setEnabled(true);
                    testButton.setText("Test Connection");
                }
            }
        };
        
        worker.execute();
    }
    
    public boolean isConfigured() {
        return configManager.isConfigured();
    }
    
    /**
     * Returns the configuration manager for external access
     */
    public ConfigurationManager getConfigurationManager() {
        return configManager;
    }
    

}
