---
tags:
  - tools
  - text
  - statistics
---

# Text Statistics

Analyseur de texte avec statistiques détaillées et métriques de lisibilité.

<div id="text-stats">
  <style>
    #text-stats {
      font-family: inherit;
    }
    #text-stats .stats-container {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
    }
    @media (max-width: 900px) {
      #text-stats .stats-container {
        grid-template-columns: 1fr;
      }
    }
    #text-stats .input-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #text-stats .results-section {
      background: var(--md-code-bg-color);
      border-radius: 8px;
      padding: 20px;
    }
    #text-stats .section-title {
      font-size: 14px;
      font-weight: 600;
      margin: 20px 0 10px 0;
      padding-bottom: 5px;
      border-bottom: 1px solid var(--md-default-fg-color--lighter);
    }
    #text-stats .section-title:first-child {
      margin-top: 0;
    }
    #text-stats textarea {
      width: 100%;
      min-height: 300px;
      padding: 15px;
      border: 1px solid var(--md-default-fg-color--lighter);
      border-radius: 4px;
      background: var(--md-default-bg-color);
      color: var(--md-default-fg-color);
      font-size: 14px;
      resize: vertical;
      box-sizing: border-box;
      line-height: 1.6;
    }
    #text-stats .stats-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 15px;
    }
    #text-stats .stat-card {
      background: var(--md-default-bg-color);
      border-radius: 8px;
      padding: 15px;
      text-align: center;
    }
    #text-stats .stat-value {
      font-size: 28px;
      font-weight: bold;
      color: var(--md-primary-fg-color);
    }
    #text-stats .stat-label {
      font-size: 11px;
      color: var(--md-default-fg-color--light);
      margin-top: 5px;
      text-transform: uppercase;
    }
    #text-stats .reading-meter {
      background: var(--md-default-bg-color);
      border-radius: 8px;
      padding: 15px;
      margin-top: 15px;
    }
    #text-stats .meter-bar {
      height: 10px;
      background: var(--md-default-fg-color--lighter);
      border-radius: 5px;
      overflow: hidden;
      margin: 10px 0;
    }
    #text-stats .meter-fill {
      height: 100%;
      transition: all 0.3s ease;
    }
    #text-stats .meter-labels {
      display: flex;
      justify-content: space-between;
      font-size: 10px;
      color: var(--md-default-fg-color--light);
    }
    #text-stats .reading-info {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 10px;
      margin-top: 15px;
    }
    #text-stats .reading-item {
      background: var(--md-code-bg-color);
      padding: 10px;
      border-radius: 4px;
      font-size: 12px;
    }
    #text-stats .reading-item strong {
      display: block;
      color: var(--md-primary-fg-color);
      font-size: 14px;
    }
    #text-stats .word-freq {
      margin-top: 15px;
    }
    #text-stats .freq-item {
      display: flex;
      justify-content: space-between;
      padding: 8px 10px;
      background: var(--md-default-bg-color);
      border-radius: 4px;
      margin-bottom: 5px;
      font-size: 13px;
    }
    #text-stats .freq-word {
      font-family: monospace;
    }
    #text-stats .freq-count {
      color: var(--md-primary-fg-color);
      font-weight: 500;
    }
    #text-stats .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 15px;
    }
    #text-stats .btn {
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      font-size: 13px;
    }
    #text-stats .btn-primary {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #text-stats .btn-secondary {
      background: var(--md-default-fg-color--lighter);
      color: var(--md-default-fg-color);
    }
    #text-stats .sample-texts {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 15px;
    }
    #text-stats .sample-btn {
      padding: 5px 10px;
      border: 1px solid var(--md-primary-fg-color);
      background: transparent;
      color: var(--md-primary-fg-color);
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
    }
    #text-stats .sample-btn:hover {
      background: var(--md-primary-fg-color);
      color: white;
    }
    #text-stats .char-breakdown {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 8px;
      margin-top: 15px;
    }
    #text-stats .char-item {
      background: var(--md-default-bg-color);
      padding: 10px;
      border-radius: 4px;
      text-align: center;
      font-size: 12px;
    }
    #text-stats .char-item strong {
      display: block;
      font-size: 18px;
      color: var(--md-primary-fg-color);
    }
  </style>

  <div class="sample-texts">
    <button class="sample-btn" onclick="loadSample('lorem')">📝 Lorem Ipsum</button>
    <button class="sample-btn" onclick="loadSample('technical')">💻 Technique</button>
    <button class="sample-btn" onclick="loadSample('simple')">📖 Simple</button>
    <button class="sample-btn" onclick="loadSample('code')">🔧 Code</button>
  </div>

  <div class="stats-container">
    <div class="input-section">
      <div class="section-title">📝 Texte à analyser</div>
      <textarea id="text-input" oninput="analyzeText()" placeholder="Collez ou tapez votre texte ici...">La programmation informatique est l'ensemble des activités qui permettent l'écriture des programmes informatiques. C'est une étape importante du développement de logiciels.

L'écriture d'un programme se fait dans un langage de programmation. Un logiciel est un ensemble de programmes qui permet de réaliser certaines tâches.

Les développeurs utilisent différents outils pour écrire, tester et déployer leurs applications. Ces outils incluent des éditeurs de code, des compilateurs, des débogueurs et des systèmes de contrôle de version.</textarea>

      <div class="actions">
        <button class="btn btn-secondary" onclick="clearText()">🗑️ Effacer</button>
        <button class="btn btn-secondary" onclick="copyStats()">📋 Copier stats</button>
      </div>
    </div>

    <div class="results-section">
      <div class="section-title">📊 Statistiques</div>
      <div class="stats-grid" id="main-stats"></div>

      <div class="section-title">📐 Détails caractères</div>
      <div class="char-breakdown" id="char-breakdown"></div>

      <div class="section-title">📚 Lisibilité</div>
      <div class="reading-meter" id="reading-meter"></div>

      <div class="section-title">🔤 Mots les plus fréquents</div>
      <div class="word-freq" id="word-freq"></div>
    </div>
  </div>
</div>

<script>
(function() {
  const samples = {
    lorem: `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris.

Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.

Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam.`,

    technical: `Le protocole HTTP (Hypertext Transfer Protocol) est un protocole de communication client-serveur développé pour le World Wide Web. Il fonctionne au-dessus de TCP/IP et utilise le port 80 par défaut.

Les méthodes HTTP principales sont GET, POST, PUT, DELETE et PATCH. Chaque requête contient des headers et potentiellement un body. Les réponses incluent un code de statut (200, 404, 500, etc.) et des données.

HTTPS ajoute une couche de chiffrement TLS/SSL pour sécuriser les échanges. Les certificats X.509 authentifient les serveurs auprès des clients.`,

    simple: `Le chat dort sur le canapé. Il fait beau aujourd'hui. Marie va au marché. Elle achète des pommes et du pain.

Les enfants jouent dans le parc. Ils sont contents. Le soleil brille. C'est une belle journée.

Papa prépare le dîner. Maman lit un livre. Tout est calme à la maison.`,

    code: `function calculateSum(numbers) {
  return numbers.reduce((acc, num) => acc + num, 0);
}

const data = [1, 2, 3, 4, 5];
const result = calculateSum(data);
console.log(\`Sum: \${result}\`);

// Output: Sum: 15`
  };

  window.loadSample = function(sample) {
    document.getElementById('text-input').value = samples[sample];
    analyzeText();
  };

  window.clearText = function() {
    document.getElementById('text-input').value = '';
    analyzeText();
  };

  window.analyzeText = function() {
    const text = document.getElementById('text-input').value;

    // Basic counts
    const chars = text.length;
    const charsNoSpaces = text.replace(/\s/g, '').length;
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    const sentences = text.split(/[.!?]+/).filter(s => s.trim()).length;
    const paragraphs = text.split(/\n\n+/).filter(p => p.trim()).length;
    const lines = text.split('\n').length;

    // Character breakdown
    const letters = (text.match(/[a-zA-ZÀ-ÿ]/g) || []).length;
    const numbers = (text.match(/[0-9]/g) || []).length;
    const spaces = (text.match(/\s/g) || []).length;
    const punctuation = (text.match(/[.,;:!?'"()\[\]{}\-_]/g) || []).length;

    // Word analysis
    const wordList = text.toLowerCase().match(/[a-zA-ZÀ-ÿ]+/g) || [];
    const avgWordLength = wordList.length ? (wordList.join('').length / wordList.length).toFixed(1) : 0;
    const avgSentenceLength = sentences ? (words / sentences).toFixed(1) : 0;

    // Reading time (average 200 wpm reading, 150 wpm speaking)
    const readingTime = Math.ceil(words / 200);
    const speakingTime = Math.ceil(words / 150);

    // Readability (Flesch-Kincaid Grade Level approximation)
    const syllables = countSyllables(text);
    const fleschScore = sentences > 0 && words > 0
      ? Math.max(0, Math.min(100, 206.835 - 1.015 * (words / sentences) - 84.6 * (syllables / words)))
      : 0;

    // Word frequency
    const wordFreq = {};
    wordList.forEach(word => {
      if (word.length > 2) {
        wordFreq[word] = (wordFreq[word] || 0) + 1;
      }
    });
    const topWords = Object.entries(wordFreq)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    // Render main stats
    document.getElementById('main-stats').innerHTML = `
      <div class="stat-card">
        <div class="stat-value">${chars.toLocaleString()}</div>
        <div class="stat-label">Caractères</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${charsNoSpaces.toLocaleString()}</div>
        <div class="stat-label">Sans espaces</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${words.toLocaleString()}</div>
        <div class="stat-label">Mots</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${sentences}</div>
        <div class="stat-label">Phrases</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${paragraphs}</div>
        <div class="stat-label">Paragraphes</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">${lines}</div>
        <div class="stat-label">Lignes</div>
      </div>
    `;

    // Character breakdown
    document.getElementById('char-breakdown').innerHTML = `
      <div class="char-item"><strong>${letters}</strong>Lettres</div>
      <div class="char-item"><strong>${numbers}</strong>Chiffres</div>
      <div class="char-item"><strong>${spaces}</strong>Espaces</div>
      <div class="char-item"><strong>${punctuation}</strong>Ponctuation</div>
    `;

    // Readability
    let readabilityLevel, readabilityColor;
    if (fleschScore >= 80) {
      readabilityLevel = 'Très facile';
      readabilityColor = '#27ae60';
    } else if (fleschScore >= 60) {
      readabilityLevel = 'Facile';
      readabilityColor = '#2ecc71';
    } else if (fleschScore >= 40) {
      readabilityLevel = 'Moyen';
      readabilityColor = '#f39c12';
    } else if (fleschScore >= 20) {
      readabilityLevel = 'Difficile';
      readabilityColor = '#e67e22';
    } else {
      readabilityLevel = 'Très difficile';
      readabilityColor = '#e74c3c';
    }

    document.getElementById('reading-meter').innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <span>Score Flesch: <strong style="color: ${readabilityColor}">${Math.round(fleschScore)}</strong></span>
        <span style="color: ${readabilityColor}; font-weight: 500;">${readabilityLevel}</span>
      </div>
      <div class="meter-bar">
        <div class="meter-fill" style="width: ${fleschScore}%; background: ${readabilityColor};"></div>
      </div>
      <div class="meter-labels">
        <span>Difficile</span>
        <span>Facile</span>
      </div>
      <div class="reading-info">
        <div class="reading-item">
          <strong>~${readingTime} min</strong>
          Temps de lecture
        </div>
        <div class="reading-item">
          <strong>~${speakingTime} min</strong>
          Temps de parole
        </div>
        <div class="reading-item">
          <strong>${avgWordLength}</strong>
          Lettres/mot (moy.)
        </div>
        <div class="reading-item">
          <strong>${avgSentenceLength}</strong>
          Mots/phrase (moy.)
        </div>
      </div>
    `;

    // Word frequency
    document.getElementById('word-freq').innerHTML = topWords.length > 0
      ? topWords.map(([word, count]) => `
          <div class="freq-item">
            <span class="freq-word">${word}</span>
            <span class="freq-count">${count}×</span>
          </div>
        `).join('')
      : '<div style="color: var(--md-default-fg-color--light); padding: 10px;">Pas assez de mots</div>';
  };

  function countSyllables(text) {
    const words = text.toLowerCase().match(/[a-zA-ZÀ-ÿ]+/g) || [];
    let count = 0;
    words.forEach(word => {
      word = word.replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, '');
      word = word.replace(/^y/, '');
      const syllables = word.match(/[aeiouy]{1,2}/g);
      count += syllables ? syllables.length : 1;
    });
    return count;
  }

  window.copyStats = function() {
    const text = document.getElementById('text-input').value;
    const chars = text.length;
    const words = text.trim() ? text.trim().split(/\s+/).length : 0;
    const sentences = text.split(/[.!?]+/).filter(s => s.trim()).length;

    const stats = `Statistiques du texte:
- Caractères: ${chars}
- Mots: ${words}
- Phrases: ${sentences}
- Temps de lecture: ~${Math.ceil(words / 200)} min`;

    navigator.clipboard.writeText(stats).then(() => {
      alert('Statistiques copiées!');
    });
  };

  // Initialize
  analyzeText();
})();
</script>

---

## Métriques de lisibilité

### Score Flesch Reading Ease

| Score | Niveau | Audience |
|-------|--------|----------|
| 90-100 | Très facile | École primaire |
| 80-89 | Facile | Collège |
| 70-79 | Assez facile | Lycée |
| 60-69 | Standard | Grand public |
| 50-59 | Assez difficile | Universitaire |
| 30-49 | Difficile | Diplômé |
| 0-29 | Très difficile | Expert |

### Formule

```
Flesch = 206.835 - (1.015 × mots/phrases) - (84.6 × syllabes/mots)
```

---

## Conseils de rédaction

- **Phrases courtes**: 15-20 mots en moyenne
- **Mots simples**: Préférer les mots courts et courants
- **Voix active**: Plus directe et plus claire
- **Un concept par phrase**: Éviter les phrases complexes
- **Paragraphes courts**: 3-5 phrases maximum
