package ghidragpt.service;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;
import ghidra.program.model.symbol.SourceType;
import ghidragpt.ui.GhidraGPTConsole;
import ghidragpt.service.GPTService;

import java.util.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

/**
 * Comprehensive code enhancement service that combines function and variable renaming
 * to make code as human-readable as possible
 */
public class CodeEnhancementService {
    
    private final DecompInterface decompiler;
    private final GPTService gptService;
    private final GhidraGPTConsole console;
    
    public CodeEnhancementService(GPTService gptService, GhidraGPTConsole console) {
        this.gptService = gptService;
        this.console = console;
        this.decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
    }
    
    /**
     * Comprehensive code enhancement: renames function and all variables for maximum readability
     */
    public EnhancementResult enhanceFunction(Function function, Program program, TaskMonitor monitor) {
        EnhancementResult result = new EnhancementResult();
        result.functionName = function.getName();
        result.originalFunctionName = function.getName();
        
        try {
            monitor.setMessage("Analyzing function for code enhancement...");
            
            // Initialize decompiler
            if (!decompiler.openProgram(program)) {
                result.errors.add("Failed to initialize decompiler");
                return result;
            }
            
            // Decompile the function
            DecompileResults decompileResults = decompiler.decompileFunction(function, 30, monitor);
            if (decompileResults == null || decompileResults.getDecompiledFunction() == null) {
                result.errors.add("Failed to decompile function: " + function.getName());
                return result;
            }
            
            HighFunction highFunction = decompileResults.getHighFunction();
            String decompiledCode = decompileResults.getDecompiledFunction().getC();
            
            // Extract variable information
            Map<String, VariableInfo> variableMap = extractVariableInformation(function, highFunction);
            
            // Generate enhancement prompt
            String enhancementPrompt = generateEnhancementPrompt(function, decompiledCode, variableMap);
            
            monitor.setMessage("Getting AI suggestions for code enhancement...");
            monitor.setProgress(30);
            
            // Get AI response with streaming (always enabled for supported providers)
            String aiResponse;
            try {
                long startTime = System.currentTimeMillis();
                GPTService.GPTProvider provider = gptService.getProvider();
                
                // Print analysis header using console
                if (console != null) {
                    console.printAnalysisHeader("✨ Code Enhancement", function.getName(), 
                        provider.toString(), gptService.getModel(), enhancementPrompt.length());
                }
                
                final StringBuilder streamBuffer = new StringBuilder();
                
                aiResponse = gptService.sendRequest(enhancementPrompt, new GPTService.StreamCallback() {
                    private boolean isFirstResponse = true;
                    
                    @Override
                    public void onPartialResponse(String partialContent) {
                        streamBuffer.append(partialContent);
                        
                        // Print header on first response
                        if (isFirstResponse) {
                            if (console != null) {
                                console.printStreamHeader();
                            }
                            isFirstResponse = false;
                        }
                        
                        // Stream response directly to console
                        if (console != null) {
                            console.appendStreamingText(partialContent);
                        }
                        
                        // Update monitor with simple streaming indicator
                        monitor.setMessage("Streaming AI response...");
                    }
                    
                    @Override
                    public void onComplete(String fullContent) {
                        long duration = System.currentTimeMillis() - startTime;
                        if (console != null) {
                            console.printStreamComplete("AI analysis", duration, fullContent.length());
                        }
                        monitor.setMessage("Processing AI suggestions...");
                        monitor.setProgress(70);
                    }
                    
                    @Override
                    public void onError(Exception error) {
                        if (console != null) {
                            console.printStreamError("AI analysis", error.getMessage());
                        }
                    }
                });
            } catch (java.net.SocketTimeoutException e) {
                throw new RuntimeException("Request timed out. Function may be too complex. Consider breaking it down into smaller functions.", e);
            } catch (java.io.IOException e) {
                if (e.getMessage().contains("timeout")) {
                    throw new RuntimeException("Network timeout occurred. Check your internet connection or try again later.", e);
                }
                throw e;
            }
            
            monitor.setProgress(70);
            
            // Parse AI response for both function and variable renames
            EnhancementSuggestions suggestions = parseEnhancementResponse(aiResponse);
            
            monitor.setMessage("Applying enhancement changes...");
            monitor.setProgress(80);
            
            // Apply the enhancement changes in a transaction
            result = applyEnhancementChanges(function, program, variableMap, suggestions, monitor);
            
            monitor.setProgress(100);
            
        } catch (Exception e) {
            String errorMsg = "Error during code enhancement: " + e.getMessage();
            
            // Provide more specific error messages for common timeout issues
            if (e.getMessage() != null && e.getMessage().toLowerCase().contains("timeout")) {
                errorMsg = "Function analysis timed out. This can happen with very large or complex functions. " +
                          "Try: 1) Check your internet connection, 2) Use a faster AI model, 3) Break down large functions, or 4) Try again later.";
            }
            
            result.errors.add(errorMsg);
            Msg.error(this, "Code enhancement error", e);
        }
        
        return result;
    }
    
    /**
     * Extract variable information from function
     */
    private Map<String, VariableInfo> extractVariableInformation(Function function, HighFunction highFunction) {
        Map<String, VariableInfo> variableMap = new HashMap<>();
        
        // Get function parameters
        Parameter[] parameters = function.getParameters();
        for (Parameter param : parameters) {
            VariableInfo info = new VariableInfo();
            info.name = param.getName();
            info.type = param.getDataType().getDisplayName();
            info.isParameter = true;
            info.variable = param;
            variableMap.put(param.getName(), info);
        }
        
        // Get local variables
        Variable[] localVars = function.getLocalVariables();
        for (Variable var : localVars) {
            if (!variableMap.containsKey(var.getName())) {
                VariableInfo info = new VariableInfo();
                info.name = var.getName();
                info.type = var.getDataType().getDisplayName();
                info.isParameter = false;
                info.variable = var;
                variableMap.put(var.getName(), info);
            }
        }
        
        // Enhance with HighSymbol information and capture ALL variables from decompiler
        if (highFunction != null) {
            Iterator<HighSymbol> symbols = highFunction.getLocalSymbolMap().getSymbols();
            while (symbols.hasNext()) {
                HighSymbol symbol = symbols.next();
                String symbolName = symbol.getName();
                
                // Update existing variable info or create new for decompiler temporaries
                VariableInfo info = variableMap.get(symbolName);
                if (info == null) {
                    // This is a decompiler temporary (iVar1, uVar1, etc.)
                    info = new VariableInfo();
                    info.name = symbolName;
                    HighVariable highVar = symbol.getHighVariable();
                    if (highVar != null) {
                        info.type = highVar.getDataType().getDisplayName();
                    } else {
                        info.type = "unknown";
                    }
                    info.isParameter = symbol.isParameter();
                    variableMap.put(symbolName, info);
                }
                
                // Set high-level information for all variables
                info.highSymbol = symbol;
                info.highVariable = symbol.getHighVariable();
            }
        }
        
        return variableMap;
    }
    
    /**
     * Generate enhancement prompt for AI analysis
     */
    private String generateEnhancementPrompt(Function function, String decompiledCode, Map<String, VariableInfo> variables) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("Analyze this decompiled function and suggest comprehensive improvements for function name, variable names, and data types.\n\n");
        prompt.append("Current function: ").append(function.getName()).append("\n\n");
        prompt.append("Decompiled code:\n").append(decompiledCode).append("\n\n");
        
        // Categorize variables for better analysis
        StringBuilder parameters = new StringBuilder();
        StringBuilder localVars = new StringBuilder();
        StringBuilder tempVars = new StringBuilder();
        StringBuilder stackVars = new StringBuilder();
        StringBuilder wellNamedVars = new StringBuilder();
        StringBuilder undefinedTypes = new StringBuilder();
        
        for (VariableInfo info : variables.values()) {
            String varDesc = "- " + info.name + " (" + info.type + ")";
            
            if (info.isParameter) {
                parameters.append(varDesc).append("\n");
            } else if (info.name.matches("^[iufl]Var\\d+$")) {
                // Decompiler temporaries like iVar1, uVar2, etc.
                tempVars.append(varDesc).append(" - decompiler temporary\n");
            } else if (info.name.matches("^[ui]Stack_\\d+$|^local_\\d+$")) {
                // Stack variables like uStack_20, local_38, etc.
                stackVars.append(varDesc).append(" - stack variable\n");
            } else if (info.name.matches("^[A-Z][a-zA-Z0-9_]*$") && info.name.length() > 3) {
                // Variables that already have reasonable names (like ControlPc, FunctionEntry)
                wellNamedVars.append(varDesc).append(" - already well-named\n");
            } else {
                localVars.append(varDesc).append("\n");
            }
            
            // Track variables with unclear types
            if (info.type.contains("undefined") || info.type.equals("int") || 
                info.type.equals("uint") || info.type.equals("void*")) {
                undefinedTypes.append("- ").append(info.name).append(" (").append(info.type)
                    .append(") - analyze usage to suggest better type\n");
            }
        }
        
        if (parameters.length() > 0) {
            prompt.append("Parameters:\n").append(parameters).append("\n");
        }
        if (localVars.length() > 0) {
            prompt.append("Local Variables:\n").append(localVars).append("\n");
        }
        if (tempVars.length() > 0) {
            prompt.append("Decompiler Temporaries (need meaningful names):\n").append(tempVars).append("\n");
        }
        if (stackVars.length() > 0) {
            prompt.append("Stack Variables (may need renaming):\n").append(stackVars).append("\n");
        }
        if (wellNamedVars.length() > 0) {
            prompt.append("Well-Named Variables (consider keeping):\n").append(wellNamedVars).append("\n");
        }
        if (undefinedTypes.length() > 0) {
            prompt.append("Variables with unclear types (suggest better types):\n").append(undefinedTypes).append("\n");
        }
        

        
        prompt.append("Analysis Instructions:\n");
        prompt.append("1. Suggest a descriptive function name based on what the function does\n");
        prompt.append("2. Rename variables to reflect their purpose/usage\n");
        prompt.append("3. For undefined types, suggest more specific types based on usage patterns\n");
        prompt.append("4. Keep well-named variables (like ControlPc, FunctionEntry) unless you have better names\n");
        prompt.append("5. Focus on renaming generic names (param_1, local_38, uStack_20, etc.)\n");
        prompt.append("6. Pay attention to:\n");
        prompt.append("   - Function parameters and their roles\n");
        prompt.append("   - Loop counters, flags, temporary storage\n");
        prompt.append("   - Return values and error codes\n");
        prompt.append("   - Data size patterns (int vs long vs pointer)\n\n");
        
        prompt.append("Answer strictly in this response format with no extra output:\n");
        prompt.append("FUNCTION_NAME: descriptive_function_name\n");
        prompt.append("RENAME: old_variable -> new_variable\n");
        prompt.append("TYPE_HINT: variable_name -> suggested_type (for unclear types)\n\n");
        
        prompt.append("Examples:\n");
        prompt.append("FUNCTION_NAME: handle_security_failure\n");
        prompt.append("RENAME: param_1 → violation_address\n");
        prompt.append("RENAME: local_38 → image_base_buffer\n");
        prompt.append("RENAME: uStack_20 → stack_parameter\n");
        prompt.append("TYPE_HINT: violation_address → PVOID\n");
        prompt.append("TYPE_HINT: image_base_buffer → DWORD64*\n");
        prompt.append("Note: Keep well-named variables like 'ControlPc' and 'FunctionEntry' unless you have significantly better names.\n");
        
        return prompt.toString();
    }
    
    /**
     * Parses AI response to extract function renames and variable renames
     * Uses simple text format only
     */
    private EnhancementSuggestions parseEnhancementResponse(String response) {
        EnhancementSuggestions suggestions = new EnhancementSuggestions();
        parseTextResponse(response, suggestions);
        return suggestions;
    }
    
    /**
     * Parse text format response
     */
    private void parseTextResponse(String response, EnhancementSuggestions suggestions) {
        // Extract function name suggestion
        Pattern functionPattern = Pattern.compile("FUNCTION_NAME:\\s*([\\w_]+)", Pattern.CASE_INSENSITIVE);
        Matcher functionMatcher = functionPattern.matcher(response);
        if (functionMatcher.find()) {
            String newFunctionName = functionMatcher.group(1).trim();
            if (isValidFunctionName(newFunctionName)) {
                suggestions.functionName = newFunctionName;
            }
        }
        
        // Extract variable renames
        Pattern renamePattern = Pattern.compile("RENAME:\\s*([\\w_]+)\\s*->\\s*([\\w_]+)", Pattern.CASE_INSENSITIVE);
        Matcher renameMatcher = renamePattern.matcher(response);
        
        while (renameMatcher.find()) {
            String oldName = renameMatcher.group(1).trim();
            String newName = renameMatcher.group(2).trim();
            
            if (isValidVariableName(newName) && !oldName.equals(newName)) {
                suggestions.variableRenames.put(oldName, newName);
            }
        }
        
        // Extract type hints
        Pattern typeHintPattern = Pattern.compile("TYPE_HINT:\\s*([\\w_]+)\\s*->\\s*([\\w_*\\[\\]]+)", Pattern.CASE_INSENSITIVE);
        Matcher typeHintMatcher = typeHintPattern.matcher(response);
        
        while (typeHintMatcher.find()) {
            String varName = typeHintMatcher.group(1).trim();
            String typeName = typeHintMatcher.group(2).trim();
            
            if (!varName.isEmpty() && !typeName.isEmpty()) {
                suggestions.typeHints.put(varName, typeName);
            }
        }
    }
    
    /**
     * Applies all enhancement changes in a single transaction
     */
    private EnhancementResult applyEnhancementChanges(Function function, Program program, 
            Map<String, VariableInfo> variableMap, EnhancementSuggestions suggestions, TaskMonitor monitor) {
        
        EnhancementResult result = new EnhancementResult();
        result.functionName = function.getName();
        result.originalFunctionName = function.getName();
        
        int transactionID = program.startTransaction("Enhance Function: " + function.getName());
        boolean success = false;
        
        try {
            // Apply function rename first
            if (suggestions.functionName != null && !suggestions.functionName.equals(function.getName())) {
                try {
                    function.setName(suggestions.functionName, SourceType.USER_DEFINED);
                    result.newFunctionName = suggestions.functionName;
                    result.functionRenamed = true;
                } catch (DuplicateNameException | InvalidInputException e) {
                    result.errors.add("Failed to rename function to " + suggestions.functionName + ": " + e.getMessage());
                }
            }
            
            // Apply variable renames using direct variable approach
            int renameCount = 0;
            for (Map.Entry<String, String> rename : suggestions.variableRenames.entrySet()) {
                String oldName = rename.getKey();
                String newName = rename.getValue();
                
                VariableInfo varInfo = variableMap.get(oldName);
                if (varInfo == null) {
                    result.errors.add("Variable not found in function scope: " + oldName);
                    continue;
                }
                
                try {
                    boolean renamed = false;
                    
                    // Single solid strategy: Direct variable renaming
                    if (varInfo.variable != null) {
                        try {
                            varInfo.variable.setName(newName, SourceType.USER_DEFINED);
                            renamed = true;
                            renameCount++;
                            result.variableRenames.put(oldName, newName);
                        } catch (DuplicateNameException | InvalidInputException e) {
                            result.errors.add("Could not rename variable " + oldName + ": " + e.getMessage());
                        }
                    } else {
                        result.errors.add("Variable " + oldName + " has no renameable reference");
                    }
                    
                } catch (Exception e) {
                    result.errors.add("Unexpected error renaming " + oldName + ": " + e.getMessage());
                }
            }
            
            // Process type hints (suggestions only - actual type changes are complex)
            int typeHintCount = 0;
            for (Map.Entry<String, String> typeHint : suggestions.typeHints.entrySet()) {
                String varName = typeHint.getKey();
                String suggestedType = typeHint.getValue();
                
                // For now, just record the type hints as suggestions
                // Actually changing types in Ghidra requires careful handling of data flow
                result.typeUpdates.put(varName, suggestedType);
                typeHintCount++;
            }
            
            success = true;
            
            // Build result message
            StringBuilder message = new StringBuilder();
            if (result.functionRenamed) {
                message.append("Function renamed: ").append(result.originalFunctionName)
                       .append(" → ").append(result.newFunctionName).append("\n");
            }
            
            if (renameCount > 0) {
                message.append("Successfully renamed ").append(renameCount).append(" variable(s)\n");
            }
            
            if (typeHintCount > 0) {
                message.append("Generated ").append(typeHintCount).append(" type suggestion(s)\n");
            }
            
            if (!result.functionRenamed && renameCount == 0 && typeHintCount == 0) {
                message.append("No enhancement changes were applied");
            }
            
            result.message = message.toString();
            
        } finally {
            program.endTransaction(transactionID, success);
        }
        
        return result;
    }
    
    /**
     * Validates function name
     */
    private boolean isValidFunctionName(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        
        // Must start with letter or underscore
        if (!Character.isLetter(name.charAt(0)) && name.charAt(0) != '_') {
            return false;
        }
        
        // Must contain only letters, digits, and underscores
        for (int i = 1; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_') {
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Validates variable name
     */
    private boolean isValidVariableName(String name) {
        return isValidFunctionName(name); // Same rules apply
    }
    
    /**
     * Clean up resources
     */
    public void dispose() {
        if (decompiler != null) {
            decompiler.dispose();
        }
    }
    
    /**
     * Holds variable information
     */
    private static class VariableInfo {
        String name;
        String type;
        boolean isParameter;
        Variable variable;
        HighSymbol highSymbol;
        HighVariable highVariable;  // For decompiler variable renaming
    }
    
    /**
     * Holds enhancement suggestions from AI
     */
    private static class EnhancementSuggestions {
        String functionName;
        Map<String, String> variableRenames = new HashMap<>();
        Map<String, String> typeHints = new HashMap<>();
    }
    
    /**
     * Result of enhancement operation
     */
    public static class EnhancementResult {
        public String functionName;
        public String originalFunctionName;
        public String newFunctionName;
        public boolean functionRenamed = false;
        public Map<String, String> variableRenames = new HashMap<>();
        public Map<String, String> typeUpdates = new HashMap<>();
        public List<String> errors = new ArrayList<>();
        public String message;
        
        public String getReport() {
            StringBuilder report = new StringBuilder();
            report.append(message).append("\n\n");
            
            if (functionRenamed) {
                report.append("Function Rename:\n");
                report.append("  ").append(originalFunctionName).append(" → ").append(newFunctionName).append("\n\n");
            }
            
            if (!variableRenames.isEmpty()) {
                report.append("Variable Renames Applied:\n");
                for (Map.Entry<String, String> rename : variableRenames.entrySet()) {
                    report.append("  ").append(rename.getKey()).append(" → ").append(rename.getValue()).append("\n");
                }
                report.append("\n");
            }
            
            if (!typeUpdates.isEmpty()) {
                report.append("Type Improvements Suggested:\n");
                for (Map.Entry<String, String> typeUpdate : typeUpdates.entrySet()) {
                    report.append("  ").append(typeUpdate.getKey()).append(" → ").append(typeUpdate.getValue()).append("\n");
                }
                report.append("\n");
            }
            
            if (!errors.isEmpty()) {
                report.append("Errors encountered:\n");
                for (String error : errors) {
                    report.append("  - ").append(error).append("\n");
                }
            }
            
            return report.toString();
        }
    }
}
