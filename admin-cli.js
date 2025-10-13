// admin-cli.js - Command-line tool for admin to manage directories and files
// Run with: node admin-cli.js <command> [options]

const fs = require('fs').promises;
const path = require('path');
const { exec } = require('child_process');
const { promisify } = require('util');
const readline = require('readline');

const execAsync = promisify(exec);

// Configuration
const UPLOAD_BASE_DIR = process.env.UPLOAD_DIR || path.resolve('./uploads');
const POWERSHELL_SCRIPTS_DIR = path.resolve('./scripts');

// Create readline interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
}

// Execute PowerShell script
async function executePowerShell(scriptName, args = []) {
  const scriptPath = path.join(POWERSHELL_SCRIPTS_DIR, scriptName);
  const argsString = args.map(arg => `"${arg}"`).join(' ');
  const command = `powershell.exe -ExecutionPolicy Bypass -File "${scriptPath}" ${argsString}`;
  
  try {
    const { stdout, stderr } = await execAsync(command);
    if (stderr) console.error('PowerShell stderr:', stderr);
    return { success: true, output: stdout };
  } catch (error) {
    console.error('PowerShell execution error:', error);
    return { success: false, error: error.message };
  }
}

// Create directory
async function createDirectory() {
  console.log('\n=== CREATE NEW DIRECTORY ===\n');
  
  const dirName = await question('Directory name (letters, numbers, hyphens, underscores only): ');
  
  if (!dirName || !/^[a-zA-Z0-9_-]+$/.test(dirName)) {
    console.log('❌ Invalid directory name!');
    return;
  }

  const description = await question('Description (optional): ');
  
  const targetPath = path.join(UPLOAD_BASE_DIR, dirName);

  try {
    // Check if directory already exists
    try {
      await fs.access(targetPath);
      console.log('❌ Directory already exists!');
      return;
    } catch {
      // Directory doesn't exist, proceed
    }

    // Create directory
    await fs.mkdir(targetPath, { recursive: true });
    console.log(`✓ Directory created: ${targetPath}`);

    // Execute PowerShell script for Windows permissions
    console.log('⚙ Setting up permissions...');
    const psResult = await executePowerShell('setup-directory.ps1', [targetPath, description || '']);
    
    if (psResult.success) {
      console.log('✓ PowerShell setup completed');
      console.log(psResult.output);
    } else {
      console.log('⚠ PowerShell setup failed:', psResult.error);
    }

    // Create metadata file
    const metaFile = path.join(targetPath, '.metadata.json');
    await fs.writeFile(metaFile, JSON.stringify({
      name: dirName,
      description: description || '',
      created: new Date().toISOString(),
      createdBy: process.env.USERNAME || 'admin'
    }, null, 2));

    console.log('✓ Metadata saved');
    console.log(`\n✅ Directory "${dirName}" created successfully!\n`);

  } catch (error) {
    console.error('❌ Error creating directory:', error.message);
  }
}

// List directories
async function listDirectories() {
  console.log('\n=== EXISTING DIRECTORIES ===\n');
  
  try {
    const entries = await fs.readdir(UPLOAD_BASE_DIR, { withFileTypes: true });
    const directories = entries.filter(entry => entry.isDirectory());

    if (directories.length === 0) {
      console.log('No directories found.');
      return;
    }

    for (const dir of directories) {
      const dirPath = path.join(UPLOAD_BASE_DIR, dir.name);
      const metaPath = path.join(dirPath, '.metadata.json');
      
      try {
        const metaContent = await fs.readFile(metaPath, 'utf-8');
        const meta = JSON.parse(metaContent);
        console.log(`📁 ${dir.name}`);
        console.log(`   Description: ${meta.description || 'N/A'}`);
        console.log(`   Created: ${new Date(meta.created).toLocaleString()}`);
        console.log('');
      } catch {
        console.log(`📁 ${dir.name}`);
        console.log(`   (No metadata available)`);
        console.log('');
      }
    }

  } catch (error) {
    console.error('❌ Error listing directories:', error.message);
  }
}

// List files in directory
async function listFiles() {
  console.log('\n=== LIST FILES IN DIRECTORY ===\n');
  
  const dirName = await question('Directory name: ');
  
  if (!dirName) {
    console.log('❌ Directory name required!');
    return;
  }

  const targetPath = path.join(UPLOAD_BASE_DIR, dirName);

  try {
    const entries = await fs.readdir(targetPath, { withFileTypes: true });
    const files = entries.filter(entry => entry.isFile() && !entry.name.startsWith('.'));

    if (files.length === 0) {
      console.log('No files found in this directory.');
      return;
    }

    console.log(`\nFiles in "${dirName}":\n`);

    for (const file of files) {
      const filePath = path.join(targetPath, file.name);
      const stats = await fs.stat(filePath);
      console.log(`📄 ${file.name}`);
      console.log(`   Size: ${formatFileSize(stats.size)}`);
      console.log(`   Modified: ${stats.mtime.toLocaleString()}`);
      console.log('');
    }

  } catch (error) {
    console.error('❌ Error listing files:', error.message);
  }
}

// Copy file to directory
async function copyFile() {
  console.log('\n=== COPY FILE TO DIRECTORY ===\n');
  
  const sourcePath = await question('Source file path: ');
  const targetDir = await question('Target directory name: ');
  
  if (!sourcePath || !targetDir) {
    console.log('❌ Both source path and target directory required!');
    return;
  }

  try {
    const sourceStats = await fs.stat(sourcePath);
    
    if (!sourceStats.isFile()) {
      console.log('❌ Source is not a file!');
      return;
    }

    const targetDirPath = path.join(UPLOAD_BASE_DIR, targetDir);
    
    // Check if target directory exists
    try {
      await fs.access(targetDirPath);
    } catch {
      console.log('❌ Target directory does not exist!');
      return;
    }

    const fileName = path.basename(sourcePath);
    const targetPath = path.join(targetDirPath, fileName);

    // Copy file
    await fs.copyFile(sourcePath, targetPath);
    
    console.log(`✓ File copied successfully!`);
    console.log(`   From: ${sourcePath}`);
    console.log(`   To: ${targetPath}`);
    console.log(`   Size: ${formatFileSize(sourceStats.size)}`);

  } catch (error) {
    console.error('❌ Error copying file:', error.message);
  }
}

// Format file size
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// Main menu
async function mainMenu() {
  console.log('\n╔════════════════════════════════════════╗');
  console.log('║   TEAM PLUS - ADMIN FILE MANAGER      ║');
  console.log('╚════════════════════════════════════════╝\n');
  console.log('1. Create new directory');
  console.log('2. List all directories');
  console.log('3. List files in directory');
  console.log('4. Copy file to directory');
  console.log('5. Exit\n');

  const choice = await question('Select option (1-5): ');

  switch (choice.trim()) {
    case '1':
      await createDirectory();
      break;
    case '2':
      await listDirectories();
      break;
    case '3':
      await listFiles();
      break;
    case '4':
      await copyFile();
      break;
    case '5':
      console.log('\nGoodbye!\n');
      rl.close();
      process.exit(0);
      return;
    default:
      console.log('❌ Invalid option!');
  }

  // Return to menu
  await mainMenu();
}

// Initialize
async function init() {
  try {
    // Ensure base directories exist
    await fs.mkdir(UPLOAD_BASE_DIR, { recursive: true });
    await fs.mkdir(POWERSHELL_SCRIPTS_DIR, { recursive: true });
    
    await mainMenu();
  } catch (error) {
    console.error('❌ Initialization error:', error.message);
    rl.close();
    process.exit(1);
  }
}

// Run
init();