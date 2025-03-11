const fs = require('fs');

// Main function to process the file
function processFile(filePath) {
  try {
    // Read the file
    const fileContent = fs.readFileSync(filePath, 'utf8');
    
    // Split the content into lines
    const lines = fileContent.split('\n');
    
    // Process each line
    for (const line of lines) {
      // Check if line starts with a number
      if (/^\d+/.test(line)) {
        // Find the position of "p: " and " k:"
        const pIndex = line.indexOf('p: ');
        const kIndex = line.indexOf(' k:');
        
        // If both markers are found and in correct order
        if (pIndex !== -1 && kIndex !== -1 && pIndex < kIndex) {
          // Extract the value between "p: " and " k:"
          const value = line.substring(pIndex + 3, kIndex);
          console.log(value);
        }
      }
    }
  } catch (error) {
    console.error(`Error processing file: ${error.message}`);
  }
}

// Check if a file path is provided as a command line argument
if (process.argv.length < 3) {
  console.log('Usage: node extract.js <file_path>');
  process.exit(1);
}

// Get the file path from command line arguments
const filePath = process.argv[2];

// Process the file
processFile(filePath);
