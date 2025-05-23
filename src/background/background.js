import { BloomFilter } from 'bloom-filters';
import { simhash } from '@biu/simhash';
import { openDB } from 'idb';

// DATABASE CONFIG
const DB_NAME = 'phishingDB';
const DB_VERSION = 1;
const URL_STORE = 'phishingUrls';
const HTML_STORE = 'htmlFingerprints';

const initDB = () => openDB(DB_NAME, DB_VERSION, {
	upgrade(db) {
		if (!db.objectStoreNames.contains(URL_STORE)) {
			db.createObjectStore(URL_STORE, { keyPath: 'url' });
		}
		if (!db.objectStoreNames.contains(HTML_STORE)) {
			db.createObjectStore(HTML_STORE, { keyPath: 'simhash' });
		}
	}
});

// BLOOMFILTER
let bloomFilter;

async function initBloomFilter() {
	const db = await initDB();
	const urls = await db.getAll(URL_STORE);
	const phishingUrls = urls.filter(u => u.result === 1).map(u => u.url);

	// bloomfilter with false positive rate of 0.001 (80k rows at hand)
	// NEVER returns false negative!
	bloomFilter = BloomFilter.from(phishingUrls, 0.001);
	console.log("Initialized bloom filter");
}

// SIMHASH
function generateSimHash(html) {
	// clean html before hashing
	const cleanHtml = html
		.replace(/<script[^>]*>.*?<\/script>/gis, '')
		.replace(/<style[^>]*>.*?<\/style>/gis, '')
		.replace(/<[^>]+>/g, ' ');

	const generatedHash = simhash([{ text: cleanHtml, weight: 1 }]);
	console.log("Generated simhash: " + generatedHash);
	return generatedHash; // returns 64 bit hash
}

async function checkSimHash(hostname, html) {
	const db = await initDB();
	const hash = generateSimHash(html);
	const entry = await db.get(HTML_STORE, hash);
	if (!entry) {
		console.log("No entry");
		return false;
	}

	if(entry.result === 0 && entry.url === hostname) {
		console.log("result=0 & url=hostname");
		return false;
	}

	if (entry.result === 1 && entry.url !== hostname) {
		console.log("result=1 & url != hostname");
		return false;
	}

	// result == 1 && url == hostname
	// result == 0 && url != hostname
	console.log(`entry: otherwise: ${entry.result} ${entry.url}`);
	return true;
}

// CSV IMPORT (One-time operation during installation of extension)
async function importCSV() {
  try {
    // Fetch the CSV file (bundled with extension)
    const csvUrl = chrome.runtime.getURL('data/transformed_data.csv');
    const response = await fetch(csvUrl);
    if (!response.ok) throw new Error('Failed to fetch CSV');
    
    const csvText = await response.text();

    // Parse CSV text
    const parsedData = await parseCSV(csvText);
    console.log(`Parsed ${parsedData.length} records from CSV`);

    // Initialize database
    const db = await initDB();
    const tx = db.transaction([URL_STORE, HTML_STORE], 'readwrite');
    
    // Prepare batch operations
    const urlStoreOps = parsedData.map(item => 
      tx.objectStore(URL_STORE).put({
        url: item.url,
        website: item.website,
        result: parseInt(item.result) || 0
      })
    );

    const htmlStoreOps = parsedData
      .filter(item => item.html_simhash)
      .map(item => 
        tx.objectStore(HTML_STORE).put({
          simhash: item.html_simhash,
          url: item.url,
          result: parseInt(item.result) || 0
        })
      );

    // Execute all operations
    await Promise.all([...urlStoreOps, ...htmlStoreOps]);
    await tx.done;
    
    console.log('CSV import completed successfully');
    return true;
  } catch (error) {
    console.error('CSV import failed:', error);
    return false;
  }
}

// CSV Parser
function parseCSV(csvText) {
  const lines = [];
  let currentLine = [];
  let inQuotes = false;
  let currentField = '';

  for (let i = 0; i < csvText.length; i++) {
    const char = csvText[i];
    const nextChar = csvText[i + 1];

    // Handle quotes
    if (char === '"') {
      if (inQuotes && nextChar === '"') {
        // Escaped quote inside quoted field
        currentField += '"';
        i++; // Skip next quote
      } else {
        // Start/end of quoted field
        inQuotes = !inQuotes;
      }
    }
    // Handle comma (only treat as separator if not in quotes)
    else if (char === ',' && !inQuotes) {
      currentLine.push(currentField);
      currentField = '';
    }
    // Handle newline (only treat as line break if not in quotes)
    else if (char === '\n' && !inQuotes) {
      currentLine.push(currentField);
      lines.push(currentLine);
      currentLine = [];
      currentField = '';
    }
    // Normal character
    else {
      currentField += char;
    }
  }

  // Add the last field and line
  if (currentField !== '' || currentLine.length > 0) {
    currentLine.push(currentField);
    lines.push(currentLine);
  }

  // Extract headers and build objects
  if (lines.length === 0) return [];
  
  const headers = lines[0].map(h => h.trim());
  return lines.slice(1)
    .map(line => {
      const obj = {};
      headers.forEach((header, i) => {
        obj[header] = i < line.length ? line[i].trim() : '';
      });
      return obj;
    })
    .filter(row => row.url && Object.values(row).some(val => val !== ''));
}

// Phishing detection
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
	if (request.type === "CHECK_URL") {
		detectPhishing(request.url, request.html).then(sendResponse);
		return true;
	}
});

async function getGeminiApiKey() {
	try {
		const db = await openDB('ExtensionDB', 1);
		const config = await db.get('config', 'geminiApiKey');
		return config?.value || null;
	} catch (err) {
		console.error(`getGeminiApiKey caught handled: ${err}`);
		return null;
	}
}

async function checkWithGeminiAPI(url, htmlContent) {
	const apiKey = await getGeminiApiKey();
	if (!apiKey) {
	  console.log('No Gemini API key configured');
	  return { isPhishing: false, method: 'gemini-missing-key' };
	}
    try {
    // Extract the most relevant portion of HTML (first 2000 chars to stay under token limits)
    const cleanHtml = htmlContent
      .replace(/<script[^>]*>.*?<\/script>/gis, '')
      .replace(/<style[^>]*>.*?<\/style>/gis, '')
      .substring(0, 2000);
    
    const prompt = `Analyze this website content and determine if it's a phishing site:
URL: ${url}
HTML Content: ${cleanHtml}

Consider these phishing indicators:
1. Suspicious domain mimicking legitimate sites
2. Requests for sensitive information
3. Poor grammar/spelling
4. Unsecured forms
5. Mismatched URLs and content

Respond ONLY with "1" for phishing or "0" for legitimate. No other text.`;

    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: prompt
          }]
        }]
      })
    });

	if (!response.ok) {
		const errorData = await response.json();
		throw new Error(`API error: ${errorData.error?.message || response.statusText}`);
	}
	
    const data = await response.json();
    const resultText = data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim();
    if (!resultText) {
          console.error('Unexpected API response format:', data);
          return { isPhishing: false, method: 'gemini-format-error' };
    }
    console.log(`Gemini returned raw text result: ${resultText}`);
    return resultText === '1' ? { isPhishing: true, method: 'gemini' } : { isPhishing: false, method: 'gemini' };
    
  } catch (error) {
    console.error('Gemini API error:', error);
    return { isPhishing: false, method: 'gemini-error' };
  }
}

async function detectPhishing(url, html) {
	// bloom filter check
	const hostname = new URL(url).hostname;
	if (!bloomFilter) {
		console.error("Bloom filter instance is null, retrying...");
		await initBloomFilter();
	}
	
	if (bloomFilter && bloomFilter.has(hostname)) {
		console.log("Entered bloom filter check");
		const db = await initDB();
		const exists = await db.get(URL_STORE, hostname);
		if (exists?.result === 1) {
			return { isPhishing: true, method: 'bloom' };
		}
	}

	// SimHash check
	if (html && await checkSimHash(hostname, html)) {
		console.log("Entered simhash check, currently seeks 100% hash match");
		return { isPhishing: true, method: 'simhash' };
	}

	// LLM check
	if (html) {
		console.log("Gemini check started");
		const geminiResult = await checkWithGeminiAPI(url, html);
		if (geminiResult.isPhishing) {
			console.log("Gemini found phishing");
			// Add to local db to avoid checking the same site again
			const db = await initDB();
			await db.put(URL_STORE, { url: hostname, result: 1 });
			return geminiResult;
		}
	}
	
	console.log("No phishing detected!");
	return { isPhishing: false };
}

// NOTIFICATION EVENT
chrome.runtime.onMessage.addListener((request) => {
	if (request.action === "show-notification") {
		chrome.notifications.create("reminder", {
			type: "basic",
			iconUrl: chrome.runtime.getURL("assets/icon48.png"),
			title: "Phishing Hunter",
			message: "WARNING: Phishing website is detected! Please check the authenticity of this website.",
			priority: 1
		});
	}	
});

// INSTALLATION
chrome.runtime.onInstalled.addListener(async () => {
	console.log("Installing...");
	await initDB();
	await importCSV();
	await initBloomFilter();
	console.log("Installation complete!");
})
