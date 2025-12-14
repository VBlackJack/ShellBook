---
tags:
  - tools
  - lorem
  - text
  - generator
  - placeholder
---

# Lorem Ipsum Generator

Generateur de texte Lorem Ipsum et autres textes de remplissage.

<div class="tool-container">

<div class="options-section">
    <h3>Options</h3>
    <div class="options-grid">
        <div class="form-group">
            <label for="text-type">Type de texte</label>
            <select id="text-type" onchange="generate()">
                <option value="lorem">Lorem Ipsum</option>
                <option value="hipster">Hipster Ipsum</option>
                <option value="bacon">Bacon Ipsum</option>
                <option value="cupcake">Cupcake Ipsum</option>
                <option value="office">Office Ipsum</option>
                <option value="cat">Cat Ipsum</option>
            </select>
        </div>
        <div class="form-group">
            <label for="unit-type">Unite</label>
            <select id="unit-type" onchange="generate()">
                <option value="paragraphs">Paragraphes</option>
                <option value="sentences">Phrases</option>
                <option value="words">Mots</option>
                <option value="bytes">Octets</option>
            </select>
        </div>
        <div class="form-group">
            <label for="count">Quantite</label>
            <input type="number" id="count" min="1" max="100" value="3" oninput="generate()">
        </div>
        <div class="form-group">
            <label for="format">Format</label>
            <select id="format" onchange="generate()">
                <option value="plain">Texte brut</option>
                <option value="html">HTML</option>
                <option value="markdown">Markdown</option>
            </select>
        </div>
    </div>
    <div class="checkbox-options">
        <label><input type="checkbox" id="start-lorem" checked onchange="generate()"> Commencer par "Lorem ipsum..."</label>
        <label><input type="checkbox" id="add-headings" onchange="generate()"> Ajouter des titres</label>
    </div>
</div>

<div class="output-section">
    <div class="output-header">
        <h4>Texte genere</h4>
        <div class="output-actions">
            <span class="char-count">Caracteres: <strong id="char-count">0</strong></span>
            <span class="word-count">Mots: <strong id="word-count">0</strong></span>
            <button onclick="copyText()" class="copy-btn">Copier</button>
            <button onclick="generate()" class="refresh-btn">Regenerer</button>
        </div>
    </div>
    <textarea id="output" readonly></textarea>
</div>

<div class="presets-section">
    <h3>Presets</h3>
    <div class="presets-grid">
        <button onclick="applyPreset('short')">Court (50 mots)</button>
        <button onclick="applyPreset('medium')">Medium (150 mots)</button>
        <button onclick="applyPreset('long')">Long (500 mots)</button>
        <button onclick="applyPreset('article')">Article (3 paragraphes)</button>
        <button onclick="applyPreset('filler')">Filler (1000 octets)</button>
    </div>
</div>

<div class="cli-section">
    <h3>Generation en CLI</h3>
    <div class="cli-grid">
        <div class="cli-card">
            <h4>Bash/Linux</h4>
            <pre># Avec curl + API
curl -s "https://loripsum.net/api/3/short"

# Generer localement
cat /dev/urandom | tr -dc 'a-zA-Z ' | head -c 500

# Avec fortune (si installe)
fortune -l</pre>
        </div>
        <div class="cli-card">
            <h4>Python</h4>
            <pre>from lorem_text import lorem

# Paragraphes
print(lorem.paragraphs(3))

# Phrases
print(lorem.sentences(5))

# Mots
print(lorem.words(50))</pre>
        </div>
    </div>
</div>

</div>

<style>
.tool-container {
    background: var(--md-code-bg-color);
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
}
.options-section, .output-section, .presets-section, .cli-section {
    background: var(--md-default-bg-color);
    padding: 20px;
    border-radius: 4px;
    margin-bottom: 20px;
}
.options-section h3, .presets-section h3, .cli-section h3 {
    margin: 0 0 15px 0;
}
.options-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
    margin-bottom: 15px;
}
.form-group label {
    display: block;
    font-size: 12px;
    font-weight: bold;
    margin-bottom: 5px;
}
.form-group input, .form-group select {
    width: 100%;
    padding: 10px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
}
.checkbox-options {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
}
.checkbox-options label {
    display: flex;
    align-items: center;
    gap: 5px;
    cursor: pointer;
}
.output-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 15px;
    flex-wrap: wrap;
    gap: 10px;
}
.output-header h4 {
    margin: 0;
}
.output-actions {
    display: flex;
    gap: 15px;
    align-items: center;
    flex-wrap: wrap;
}
.char-count, .word-count {
    font-size: 12px;
    color: var(--md-default-fg-color--light);
}
.copy-btn, .refresh-btn {
    padding: 8px 15px;
    background: var(--md-primary-fg-color);
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
}
.refresh-btn {
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
}
#output {
    width: 100%;
    min-height: 300px;
    padding: 15px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    background: var(--md-code-bg-color);
    color: var(--md-default-fg-color);
    resize: vertical;
}
.presets-grid {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
}
.presets-grid button {
    padding: 10px 20px;
    background: var(--md-code-bg-color);
    border: 1px solid var(--md-default-fg-color--lighter);
    border-radius: 4px;
    cursor: pointer;
    color: var(--md-default-fg-color);
}
.presets-grid button:hover {
    background: var(--md-primary-fg-color);
    color: white;
}
.cli-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 15px;
}
.cli-card {
    background: var(--md-code-bg-color);
    padding: 15px;
    border-radius: 4px;
}
.cli-card h4 {
    margin: 0 0 10px 0;
}
.cli-card pre {
    margin: 0;
    padding: 10px;
    background: #1e1e1e;
    color: #d4d4d4;
    border-radius: 4px;
    font-size: 12px;
    overflow-x: auto;
}
</style>

<script>
const TEXTS = {
    lorem: {
        words: ['lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit', 'sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore', 'et', 'dolore', 'magna', 'aliqua', 'enim', 'ad', 'minim', 'veniam', 'quis', 'nostrud', 'exercitation', 'ullamco', 'laboris', 'nisi', 'aliquip', 'ex', 'ea', 'commodo', 'consequat', 'duis', 'aute', 'irure', 'in', 'reprehenderit', 'voluptate', 'velit', 'esse', 'cillum', 'fugiat', 'nulla', 'pariatur', 'excepteur', 'sint', 'occaecat', 'cupidatat', 'non', 'proident', 'sunt', 'culpa', 'qui', 'officia', 'deserunt', 'mollit', 'anim', 'id', 'est', 'laborum', 'porta', 'nibh', 'venenatis', 'cras', 'fermentum', 'odio', 'faucibus', 'scelerisque', 'eleifend', 'donec', 'pretium', 'vulputate', 'sapien', 'nec', 'sagittis', 'aliquam', 'malesuada', 'bibendum', 'arcu', 'vitae', 'elementum', 'curabitur', 'gravida', 'blandit', 'massa', 'erat', 'nam', 'libero', 'justo', 'laoreet', 'mattis', 'ultrices', 'auctor', 'augue', 'mauris'],
        start: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit'
    },
    hipster: {
        words: ['artisan', 'authentic', 'bicycle', 'brooklyn', 'craft', 'beard', 'blog', 'brunch', 'coffee', 'cold-pressed', 'distillery', 'dreamcatcher', 'echo', 'ethical', 'farm-to-table', 'fixie', 'flannel', 'gastropub', 'gentrify', 'gluten-free', 'hashtag', 'helvetica', 'hoodie', 'intelligentsia', 'irony', 'jean', 'kale', 'keytar', 'kickstarter', 'kinfolk', 'kombucha', 'letterpress', 'lomo', 'meditation', 'messenger', 'microdosing', 'mustache', 'narwhal', 'organic', 'photo', 'pitchfork', 'polaroid', 'portland', 'post-ironic', 'quinoa', 'raw', 'retro', 'scenester', 'selvage', 'shabby', 'shoreditch', 'single-origin', 'skateboard', 'slow-carb', 'small', 'sriracha', 'street', 'sustainable', 'tattooed', 'thundercats', 'tofu', 'tote', 'tumblr', 'twee', 'typewriter', 'umami', 'urban', 'vegan', 'venmo', 'vinyl', 'viral', 'wayfarers', 'williamsburg', 'wolf', 'yolo', 'you'],
        start: 'Artisan authentic bicycle rights brooklyn'
    },
    bacon: {
        words: ['bacon', 'beef', 'biltong', 'boudin', 'bresaola', 'brisket', 'burgdoggen', 'capicola', 'chicken', 'chislic', 'chorizo', 'corned', 'cow', 'cupim', 'drumstick', 'fatback', 'filet', 'flank', 'frankfurter', 'ground', 'ham', 'hamburger', 'hock', 'jowl', 'kevin', 'kielbasa', 'landjaeger', 'leberkas', 'loin', 'meatball', 'meatloaf', 'pastrami', 'pork', 'porchetta', 'prosciutto', 'ribeye', 'ribs', 'rump', 'salami', 'sausage', 'shank', 'shankle', 'short', 'sirloin', 'spare', 'speck', 'steak', 'strip', 't-bone', 'tail', 'tenderloin', 'tongue', 'tri-tip', 'turkey', 'venison'],
        start: 'Bacon ipsum dolor amet beef biltong boudin'
    },
    cupcake: {
        words: ['apple', 'bear', 'biscuit', 'bonbon', 'brownie', 'cake', 'candy', 'caramels', 'cheesecake', 'choco', 'chocolate', 'chupa', 'chups', 'cotton', 'croissant', 'cupcake', 'danish', 'dessert', 'donut', 'dragee', 'drops', 'fruitcake', 'gingerbread', 'gummi', 'gummies', 'halvah', 'ice', 'jelly', 'jujubes', 'lemon', 'licorice', 'lollipop', 'macaroon', 'marzipan', 'muffin', 'oat', 'pastry', 'pie', 'powder', 'pudding', 'roll', 'sesame', 'snaps', 'souffles', 'sugar', 'sweet', 'tart', 'tiramisu', 'topping', 'tootsie', 'wafer'],
        start: 'Cupcake ipsum dolor sit amet chocolate'
    },
    office: {
        words: ['action', 'agenda', 'alignment', 'bandwidth', 'baseline', 'benchmark', 'best', 'bottom', 'brand', 'circle', 'client', 'core', 'deliverable', 'deploy', 'disrupt', 'drill', 'driver', 'ecosystem', 'empower', 'engagement', 'evangelize', 'execute', 'framework', 'growth', 'hack', 'holistic', 'ideate', 'impact', 'innovate', 'iterate', 'journey', 'key', 'kpi', 'lean', 'leverage', 'line', 'loop', 'low-hanging', 'metric', 'milestone', 'mindset', 'move', 'needle', 'next', 'north', 'on-brand', 'organic', 'outside', 'paradigm', 'pivot', 'practice', 'proactive', 'reach', 'rock', 'roi', 'runway', 'scalable', 'scope', 'seamless', 'silo', 'stakeholder', 'star', 'strategy', 'streamline', 'synergy', 'takeaway', 'team', 'think', 'thought', 'tiger', 'touch', 'value', 'vertical', 'vision', 'win-win'],
        start: 'Let me circle back on this action item'
    },
    cat: {
        words: ['attack', 'bird', 'box', 'catnip', 'chase', 'climb', 'claw', 'cuddle', 'curtains', 'destroy', 'eat', 'explore', 'feather', 'fish', 'fluffy', 'fur', 'groom', 'hairball', 'hide', 'hiss', 'hunt', 'ignore', 'jump', 'keyboard', 'kitten', 'lap', 'laser', 'lick', 'loaf', 'meow', 'mouse', 'nap', 'owner', 'paw', 'play', 'pounce', 'purr', 'run', 'scratch', 'shed', 'sit', 'sleep', 'snuggle', 'stare', 'stretch', 'string', 'sunbeam', 'tail', 'toy', 'treat', 'tuna', 'whiskers', 'yarn', 'zoomies'],
        start: 'Cat ipsum dolor sit amet meow purr'
    }
};

function randomWord(type) {
    const words = TEXTS[type].words;
    return words[Math.floor(Math.random() * words.length)];
}

function capitalize(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

function generateSentence(type, wordCount = null) {
    const count = wordCount || Math.floor(Math.random() * 10) + 5;
    let words = [];
    for (let i = 0; i < count; i++) {
        words.push(randomWord(type));
    }
    return capitalize(words.join(' ')) + '.';
}

function generateParagraph(type, sentenceCount = null) {
    const count = sentenceCount || Math.floor(Math.random() * 4) + 3;
    let sentences = [];
    for (let i = 0; i < count; i++) {
        sentences.push(generateSentence(type));
    }
    return sentences.join(' ');
}

function generate() {
    const type = document.getElementById('text-type').value;
    const unit = document.getElementById('unit-type').value;
    const count = parseInt(document.getElementById('count').value) || 1;
    const format = document.getElementById('format').value;
    const startLorem = document.getElementById('start-lorem').checked;
    const addHeadings = document.getElementById('add-headings').checked;

    let result = [];

    if (unit === 'paragraphs') {
        for (let i = 0; i < count; i++) {
            let para = generateParagraph(type);
            if (i === 0 && startLorem) {
                para = TEXTS[type].start + '. ' + para;
            }
            if (addHeadings && format !== 'plain') {
                const heading = capitalize(randomWord(type)) + ' ' + capitalize(randomWord(type));
                if (format === 'html') {
                    result.push(`<h2>${heading}</h2>\n<p>${para}</p>`);
                } else {
                    result.push(`## ${heading}\n\n${para}`);
                }
            } else if (format === 'html') {
                result.push(`<p>${para}</p>`);
            } else {
                result.push(para);
            }
        }
    } else if (unit === 'sentences') {
        let sentences = [];
        for (let i = 0; i < count; i++) {
            sentences.push(generateSentence(type));
        }
        if (startLorem) {
            sentences[0] = TEXTS[type].start + '. ' + sentences[0];
        }
        result = [sentences.join(' ')];
    } else if (unit === 'words') {
        let words = [];
        if (startLorem) {
            words = TEXTS[type].start.split(' ');
        }
        while (words.length < count) {
            words.push(randomWord(type));
        }
        result = [capitalize(words.slice(0, count).join(' '))];
    } else if (unit === 'bytes') {
        let text = '';
        while (text.length < count) {
            text += generateParagraph(type) + ' ';
        }
        if (startLorem) {
            text = TEXTS[type].start + '. ' + text;
        }
        result = [text.substring(0, count)];
    }

    const separator = format === 'html' ? '\n\n' : '\n\n';
    const output = result.join(separator);

    document.getElementById('output').value = output;
    document.getElementById('char-count').textContent = output.length;
    document.getElementById('word-count').textContent = output.split(/\s+/).filter(w => w).length;
}

function copyText() {
    const output = document.getElementById('output');
    output.select();
    document.execCommand('copy');

    const btn = event.target;
    btn.textContent = 'Copie!';
    setTimeout(() => { btn.textContent = 'Copier'; }, 1000);
}

function applyPreset(preset) {
    switch (preset) {
        case 'short':
            document.getElementById('unit-type').value = 'words';
            document.getElementById('count').value = 50;
            break;
        case 'medium':
            document.getElementById('unit-type').value = 'words';
            document.getElementById('count').value = 150;
            break;
        case 'long':
            document.getElementById('unit-type').value = 'words';
            document.getElementById('count').value = 500;
            break;
        case 'article':
            document.getElementById('unit-type').value = 'paragraphs';
            document.getElementById('count').value = 3;
            document.getElementById('add-headings').checked = true;
            break;
        case 'filler':
            document.getElementById('unit-type').value = 'bytes';
            document.getElementById('count').value = 1000;
            break;
    }
    generate();
}

// Initialize
generate();
</script>
