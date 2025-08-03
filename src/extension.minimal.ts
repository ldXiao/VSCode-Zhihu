"use strict";

import * as vscode from "vscode";

export async function activate(context: vscode.ExtensionContext) {
    console.log("Zhihu Extension Activated - Minimal Version");
    
    // Register a simple login command to test
    const loginCommand = vscode.commands.registerCommand('zhihu.login', () => {
        vscode.window.showInformationMessage('Zhihu Login - Minimal Version Working!');
    });
    
    // Register other essential commands
    const refreshFeedCommand = vscode.commands.registerCommand('zhihu.refreshFeed', () => {
        vscode.window.showInformationMessage('Refresh Feed - Feature in development');
    });
    
    const publishCommand = vscode.commands.registerCommand('zhihu.publish', () => {
        vscode.window.showInformationMessage('Publish - Feature in development');
    });
    
    const searchCommand = vscode.commands.registerCommand('zhihu.search', () => {
        vscode.window.showInformationMessage('Search - Feature in development');
    });
    
    // Add commands to context
    context.subscriptions.push(loginCommand);
    context.subscriptions.push(refreshFeedCommand);
    context.subscriptions.push(publishCommand);
    context.subscriptions.push(searchCommand);
    
    console.log("Zhihu Extension - All commands registered successfully");
}

export function deactivate() {
    console.log("Zhihu Extension Deactivated");
}
