package ghidragpt.analyzer;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidragpt.service.CodeAnalysisService;
import ghidragpt.service.GPTService;

/**
 * Automated analyzer that can run GPT analysis on functions during auto-analysis
 */
public class GPTFunctionAnalyzer extends AbstractAnalyzer {
    
    private static final String NAME = "GPT Function Analyzer";
    private static final String DESCRIPTION = "Analyzes functions using GPT models for enhanced reverse engineering";
    
    private static final String OPTION_API_KEY = "API Key";
    private static final String OPTION_PROVIDER = "Provider";
    private static final String OPTION_MODEL = "Model";
    private static final String OPTION_AUTO_RENAME = "Auto-rename variables";
    private static final String OPTION_ADD_COMMENTS = "Add explanatory comments";
    
    private GPTService gptService;
    private CodeAnalysisService analysisService;
    private boolean autoRename = false;
    private boolean addComments = true;
    
    public GPTFunctionAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
        setSupportsOneTimeAnalysis();
        gptService = new GPTService();
    }
    
    @Override
    public boolean getDefaultEnablement(Program program) {
        // Disabled by default since it requires API configuration
        return false;
    }
    
    @Override
    public boolean canAnalyze(Program program) {
        return true;
    }
    
    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPTION_API_KEY, "", null, "API key for GPT service");
        options.registerOption(OPTION_PROVIDER, GPTService.GPTProvider.OPENAI, null, "GPT service provider");
        options.registerOption(OPTION_MODEL, "gpt-4", null, "Model to use for analysis");
        options.registerOption(OPTION_AUTO_RENAME, autoRename, null, "Automatically rename variables based on GPT suggestions");
        options.registerOption(OPTION_ADD_COMMENTS, addComments, null, "Add explanatory comments to functions");
    }
    
    @Override
    public void optionsChanged(Options options, Program program) {
        String apiKey = options.getString(OPTION_API_KEY, "");
        GPTService.GPTProvider provider = options.getEnum(OPTION_PROVIDER, GPTService.GPTProvider.OPENAI);
        String model = options.getString(OPTION_MODEL, "gpt-4");
        autoRename = options.getBoolean(OPTION_AUTO_RENAME, false);
        addComments = options.getBoolean(OPTION_ADD_COMMENTS, true);
        
        if (!apiKey.isEmpty()) {
            gptService.setApiKey(apiKey);
            gptService.setProvider(provider);
            gptService.setModel(model);
        }
    }
    
    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        
        // Initialize analysis service with null console (analyzer context)
        analysisService = new CodeAnalysisService(gptService, null);
        analysisService.initializeDecompiler(program);
        
        try {
            // Get functions in the address set
            FunctionIterator functionIterator = program.getFunctionManager().getFunctions(set, true);
            
            int functionCount = 0;
            for (Function function : functionIterator) {
                functionCount++;
            }
            
            if (functionCount == 0) {
                return true;
            }
            
            monitor.initialize(functionCount);
            monitor.setMessage("Analyzing functions with GPT...");
            
            functionIterator = program.getFunctionManager().getFunctions(set, true);
            int progress = 0;
            
            for (Function function : functionIterator) {
                monitor.checkCancelled();
                monitor.setMessage("Analyzing function: " + function.getName());
                monitor.setProgress(progress++);
                
                try {
                    analyzeFunction(function, program, monitor, log);
                } catch (Exception e) {
                    log.appendMsg("Failed to analyze function " + function.getName() + ": " + e.getMessage());
                }
            }
            
            return true;
            
        } finally {
            if (analysisService != null) {
                analysisService.dispose();
            }
        }
    }
    
    private void analyzeFunction(Function function, Program program, TaskMonitor monitor, MessageLog log) {
        try {
            if (addComments) {
                // Get function explanation and add as comment
                String explanation = analysisService.explainFunction(function, program, monitor);
                if (explanation != null && !explanation.isEmpty()) {
                    function.setComment("GPT Analysis: " + explanation);
                }
            }
            
            if (autoRename) {
                // Use comprehensive enhancement instead of just variable suggestions
                String enhancementResult = analysisService.enhanceFunction(function, program, monitor);
                if (enhancementResult != null && !enhancementResult.isEmpty()) {
                    log.appendMsg("Enhancement result for " + function.getName() + ": " + enhancementResult);
                }
            }
            
            // Always check for vulnerabilities and log them
            String vulnerabilities = analysisService.detectVulnerabilities(function, program, monitor);
            if (vulnerabilities != null && !vulnerabilities.toLowerCase().contains("no vulnerabilities") 
                && !vulnerabilities.toLowerCase().contains("no obvious")) {
                log.appendMsg("SECURITY: Potential vulnerabilities in " + function.getName() + ": " + vulnerabilities);
            }
            
        } catch (Exception e) {
            log.appendMsg("Error analyzing function " + function.getName() + ": " + e.getMessage());
        }
    }
}
