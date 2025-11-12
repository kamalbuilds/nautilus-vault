/**
 * Global Jest Teardown
 * Runs once after all tests
 */

const fs = require('fs').promises;
const path = require('path');

module.exports = async () => {
  console.log('🧹 Cleaning up test environment...');

  // Calculate test duration
  const duration = Date.now() - (global.__TEST_START_TIME__ || 0);
  console.log(`⏱️ Total test duration: ${duration}ms`);

  // Clean up temporary files
  const tempDir = path.join(__dirname, '../temp');
  try {
    const files = await fs.readdir(tempDir);
    await Promise.all(
      files.map(file => fs.unlink(path.join(tempDir, file)))
    );
  } catch (error) {
    // Temp directory might not exist, ignore
  }

  // Generate test summary report
  const reportPath = path.join(__dirname, '../logs/test-summary.json');
  const report = {
    timestamp: new Date().toISOString(),
    duration,
    environment: process.env.NODE_ENV,
    nodeVersion: process.version
  };

  try {
    await fs.writeFile(reportPath, JSON.stringify(report, null, 2));
  } catch (error) {
    console.warn('Warning: Could not write test summary:', error.message);
  }

  console.log('✅ Cleanup complete');
};