package ghidragpt;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidragpt.ui.GhidraGPTProvider;
import ghidragpt.service.GPTService;
import ghidragpt.config.ConfigurationManager;

import javax.swing.*;

/**
 * Main plugin class for GhidraGPT - integrates GPT models into Ghidra for code analysis
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "GhidraGPT",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "GPT Integration for Ghidra",
    description = "Integrates GPT models (OpenAI GPT, Anthropic Claude, etc.) into Ghidra for " +
                  "automated code analysis, variable renaming, vulnerability detection, and explanation generation."
)
public class GhidraGPTPlugin extends ProgramPlugin {
    
    private GhidraGPTProvider provider;
    private GPTService gptService;
    private ConfigurationManager configManager;
    private boolean configurationChecked = false;
    
    public GhidraGPTPlugin(PluginTool tool) {
        super(tool);
        gptService = new GPTService();
        configManager = new ConfigurationManager();
    }
    
    @Override
    protected void init() {
        super.init();
        provider = new GhidraGPTProvider(this, getName());
        
        // Check configuration on startup
        checkAndShowConfigurationIfNeeded();
    }
    
    private void checkAndShowConfigurationIfNeeded() {
        if (!configurationChecked) {
            configurationChecked = true;
            
            if (!configManager.configurationFileExists() || !configManager.isConfigured()) {
                SwingUtilities.invokeLater(() -> {
                    int choice = JOptionPane.showConfirmDialog(
                        getTool().getActiveWindow(),
                        "GhidraGPT is not configured yet.\n\n" +
                        "Would you like to configure it now?\n" +
                        "You can always configure it later from the GhidraGPT panel.",
                        "GhidraGPT Configuration Required",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE
                    );
                    
                    if (choice == JOptionPane.YES_OPTION) {
                        if (provider != null) {
                            provider.setVisible(true);
                            provider.showConfigurationTab();
                        }
                    }
                });
            } else {
                gptService.setApiKey(configManager.getApiKey());
                gptService.setProvider(configManager.getProvider());
                gptService.setModel(configManager.getModel());
                gptService.setMaxTokens(configManager.getMaxTokens());
                gptService.setTemperature(configManager.getTemperature());
                gptService.setTimeoutSeconds(configManager.getTimeoutSeconds());
                
                Msg.info(this, "GhidraGPT configuration loaded successfully. Provider: " + 
                    configManager.getProvider() + ", Model: " + configManager.getModel() + 
                    ", Timeout: " + configManager.getTimeoutSeconds() + "s");
            }
        }
    }
    
    @Override
    protected void programActivated(Program program) {
        if (provider != null) {
            provider.programActivated(program);
        }
        checkAndShowConfigurationIfNeeded();
    }
    
    @Override
    protected void programDeactivated(Program program) {
        if (provider != null) {
            provider.programDeactivated(program);
        }
    }
    
    @Override
    protected void dispose() {
        if (provider != null) {
            provider.dispose();
        }
        super.dispose();
    }
    
    public GPTService getGPTService() {
        return gptService;
    }
}
