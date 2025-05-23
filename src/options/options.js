import { openDB } from 'idb';

// Initialize or upgrade the database
async function initDB() {
  return await openDB('ExtensionDB', 1, {
    upgrade(db) {
      if (!db.objectStoreNames.contains('config')) {
        db.createObjectStore('config', { keyPath: 'id' });
      }
    }
  });
}

document.getElementById('save').addEventListener('click', async () => {
  const apiKey = document.getElementById('apiKey').value.trim();
  
  if (!apiKey) {
    showStatus('Please enter an API key', 'red');
    return;
  }

  try {
    // Initialize database before using it
    const db = await initDB();
    await db.put('config', { 
      id: 'geminiApiKey', 
      value: apiKey 
    });
    showStatus('API key saved successfully!', 'green');
  } catch (error) {
    showStatus('Failed to save API key', 'red');
    console.error('Database error:', error);
  }
});

// Load saved key if exists
async function loadSavedKey() {
  try {
    const db = await initDB();
    const config = await db.get('config', 'geminiApiKey');
    if (config?.value) {
      document.getElementById('apiKey').value = config.value;
    }
  } catch (error) {
    console.error('Failed to load API key:', error);
  }
}

function showStatus(message, color) {
  const status = document.getElementById('status');
  status.textContent = message;
  status.style.color = color;
  setTimeout(() => status.textContent = '', 3000);
}

// Initialize on page load
loadSavedKey();
