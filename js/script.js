// Глобальные переменные
let lastResults = { subdomains: [], ips: [], grouped: [] };
let showIPDetails = true;
let dnsCache = new Map();

// Утилиты для работы с IP
function ipToNumber(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
}

function numberToIp(num) {
  return [
    (num >>> 24) & 255,
    (num >>> 16) & 255,
    (num >>> 8) & 255,
    num & 255
  ].join('.');
}

// Функция для группировки IP по подсетям
function groupIPsBySubnet(ips) {
  if (!ips.length) return [];
  
  // Сначала попробуем различные варианты группировки
  const groups = new Map();
  
  ips.forEach(ip => {
    const parts = ip.split('.').map(p => parseInt(p));
    const [a, b, c, d] = parts;
    
    // Группируем по различным маскам подсетей
    const groupKeys = [
      `${a}.${b}.${c}`, // /24 маска
      `${a}.${b}`,      // /16 маска  
      `${a}`            // /8 маска
    ];
    
    // Находим наиболее подходящую группу
    let bestGroup = null;
    for (const key of groupKeys) {
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key).push(ip);
      
      // Если это первая группа с более чем 1 IP, используем её
      if (!bestGroup && groups.get(key).length > 1) {
        bestGroup = key;
      }
    }
  });
  
  const result = [];
  const processedIPs = new Set();
  
  // Сначала обрабатываем группы по /24
  for (const [key, groupIps] of groups.entries()) {
    if (key.split('.').length === 3 && groupIps.length >= 2) {
      const uniqueIps = [...new Set(groupIps)];
      if (uniqueIps.some(ip => !processedIPs.has(ip))) {
        const subnet = calculateOptimalSubnet(uniqueIps);
        result.push(subnet);
        uniqueIps.forEach(ip => processedIPs.add(ip));
      }
    }
  }
  
  // Затем группы по /16
  for (const [key, groupIps] of groups.entries()) {
    if (key.split('.').length === 2 && groupIps.length >= 3) {
      const uniqueIps = [...new Set(groupIps)].filter(ip => !processedIPs.has(ip));
      if (uniqueIps.length >= 2) {
        const subnet = calculateOptimalSubnet(uniqueIps);
        result.push(subnet);
        uniqueIps.forEach(ip => processedIPs.add(ip));
      }
    }
  }
  
  // Оставшиеся IP как отдельные /32
  ips.forEach(ip => {
    if (!processedIPs.has(ip)) {
      result.push({
        subnet: ip + '/32',
        ips: [ip]
      });
    }
  });
  
  return result.sort((a, b) => {
    // Сортируем по IP адресу
    const aIP = a.ips[0].split('.').map(n => parseInt(n));
    const bIP = b.ips[0].split('.').map(n => parseInt(n));
    
    for (let i = 0; i < 4; i++) {
      if (aIP[i] !== bIP[i]) {
        return aIP[i] - bIP[i];
      }
    }
    return 0;
  });
}

// Функция для вычисления оптимальной подсети
function calculateOptimalSubnet(ips) {
  if (ips.length === 1) {
    return { subnet: ips[0] + '/32', ips: ips };
  }
  
  // Конвертируем IP в числа
  const numbers = ips.map(ip => {
    const parts = ip.split('.').map(p => parseInt(p));
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
  });
  
  const min = Math.min(...numbers);
  const max = Math.max(...numbers);
  
  // Находим количество общих битов
  let mask = 32;
  let diff = min ^ max;
  
  while (diff > 0) {
    diff >>>= 1;
    mask--;
  }
  
  // Вычисляем сетевой адрес
  const network = min & (0xFFFFFFFF << (32 - mask));
  
  // Конвертируем обратно в IP
  const networkIP = [
    (network >>> 24) & 255,
    (network >>> 16) & 255,
    (network >>> 8) & 255,
    network & 255
  ].join('.');
  
  return {
    subnet: `${networkIP}/${mask}`,
    ips: ips.sort((a, b) => {
      const aNum = a.split('.').map(n => parseInt(n));
      const bNum = b.split('.').map(n => parseInt(n));
      for (let i = 0; i < 4; i++) {
        if (aNum[i] !== bNum[i]) return aNum[i] - bNum[i];
      }
      return 0;
    })
  };
}

// Основные функции
async function fetchSubdomainsFromCRT(domain) {
  const url = `https://crt.sh/?q=%25.${domain}&output=json`;
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Ошибка запроса: ${res.status}`);
    const data = await res.json();

    const subdomains = new Set();
    data.forEach(entry => {
      const lines = entry.name_value.split('\n');
      lines.forEach(line => {
        if (line.endsWith(domain)) subdomains.add(line.trim());
      });
    });

    return Array.from(subdomains).sort();
  } catch (err) {
    console.error(err);
    return [];
  }
}

async function resolveIP(subdomain) {
  // Проверяем кэш
  if (dnsCache.has(subdomain)) {
    return dnsCache.get(subdomain);
  }
  
  const dnsUrl = `https://dns.google/resolve?name=${subdomain}&type=A`;
  try {
    const res = await fetch(dnsUrl);
    const data = await res.json();
    let ips = [];
    
    if (data.Answer) {
      ips = data.Answer
        .filter(ans => ans.type === 1)
        .map(ans => ans.data);
    }
    
    // Кэшируем результат
    dnsCache.set(subdomain, ips);
    return ips;
  } catch (err) {
    dnsCache.set(subdomain, []);
    return [];
  }
}

// Параллельное разрешение DNS с прогресс баром
async function resolveIPsParallel(subdomains) {
  const progressContainer = document.getElementById('progressContainer');
  const progressBar = document.getElementById('progressBar');
  const progressText = document.getElementById('progressText');
  
  progressContainer.style.display = 'block';
  progressBar.style.width = '0%';
  progressText.textContent = 'Разрешение IP-адресов...';
  
  const batchSize = 5; // Количество параллельных запросов
  const results = [];
  
  for (let i = 0; i < subdomains.length; i += batchSize) {
    const batch = subdomains.slice(i, i + batchSize);
    const batchPromises = batch.map(subdomain => resolveIP(subdomain));
    
    const batchResults = await Promise.all(batchPromises);
    results.push(...batchResults);
    
    // Обновляем прогресс
    const progress = Math.min(100, ((i + batchSize) / subdomains.length) * 100);
    progressBar.style.width = progress + '%';
    progressText.textContent = `Обработано ${Math.min(i + batchSize, subdomains.length)} из ${subdomains.length} поддоменов`;
    
    // Небольшая задержка для избежания rate limiting
    if (i + batchSize < subdomains.length) {
      await new Promise(resolve => setTimeout(resolve, 200));
    }
  }
  
  progressContainer.style.display = 'none';
  return results;
}

// Форматирование результатов
function formatSubdomainResults(subdomains) {
  if (!subdomains.length) return '❌ Поддомены не найдены.';
  
  let result = `✅ Найдено ${subdomains.length} поддоменов:\n\n`;
  subdomains.forEach(subdomain => {
    result += `${subdomain}\n`;
  });
  
  return result;
}

function formatIPResults(ips, showDetails = false) {
  if (!ips.length) return '❌ IP-адреса не найдены.';
  
  const grouped = groupIPsBySubnet(ips);
  let result = `✅ Найдено ${ips.length} уникальных IP-адресов:\n\n`;
  
  result += '📊 ПОДСЕТИ (CIDR):\n';
  grouped.forEach(group => {
    result += `${group.subnet}\n`;
  });
  
  if (showDetails) {
    result += '\n📋 ДЕТАЛИ ПО ПОДСЕТЯМ:\n';
    grouped.forEach(group => {
      if (group.ips.length > 1) {
        result += `\n${group.subnet}:\n`;
        group.ips.forEach(ip => result += `  • ${ip}\n`);
      }
    });
  }
  
  result += '\n' + '─'.repeat(40) + '\n';
  result += '📝 ВСЕ IP (построчно):\n';
  ips.forEach(ip => result += `${ip}\n`);
  
  lastResults.grouped = grouped;
  return result;
}

// Основная функция поиска
async function search() {
  const domain = document.getElementById('domainInput').value.trim();
  const subOutput = document.getElementById('subOutput');
  const ipOutput = document.getElementById('ipOutput');
  
  if (!domain) {
    alert('Введите домен для поиска');
    return;
  }
  
  // Сброс результатов
  subOutput.textContent = `🔍 Поиск поддоменов для ${domain} через crt.sh...`;
  ipOutput.textContent = `🌐 Ожидание разрешения IP...`;
  
  try {
    // Получаем поддомены
    const subdomains = await fetchSubdomainsFromCRT(domain);
    
    if (!subdomains.length) {
      subOutput.textContent = '❌ Поддомены не найдены.';
      ipOutput.textContent = '';
      lastResults = { subdomains: [], ips: [], grouped: [] };
      return;
    }
    
    subOutput.textContent = formatSubdomainResults(subdomains);
    
    // Параллельное разрешение IP
    const ipResults = await resolveIPsParallel(subdomains);
    
    // Собираем уникальные IP
    const ipSet = new Set();
    ipResults.forEach(ips => {
      ips.forEach(ip => ipSet.add(ip));
    });
    
    const sortedIPs = Array.from(ipSet).sort();
    ipOutput.textContent = formatIPResults(sortedIPs, showIPDetails);
    
    // Сохраняем результаты
    lastResults = {
      domain,
      subdomains,
      ips: sortedIPs,
      grouped: groupIPsBySubnet(sortedIPs)
    };
    
  } catch (error) {
    console.error('Ошибка поиска:', error);
    subOutput.textContent = '❌ Произошла ошибка при поиске';
    ipOutput.textContent = '';
  }
}

// Управление отображением
function toggleIPView() {
  showIPDetails = !showIPDetails;
  const toggleBtn = document.getElementById('toggleBtn');
  toggleBtn.textContent = showIPDetails ? 'Простой вид IP' : 'Детальный вид IP';
  
  if (lastResults.ips.length > 0) {
    const ipOutput = document.getElementById('ipOutput');
    ipOutput.textContent = formatIPResults(lastResults.ips, showIPDetails);
  }
}

// Функции копирования
function copyToClipboard(elementId) {
  const element = document.getElementById(elementId);
  navigator.clipboard.writeText(element.textContent)
    .then(() => showNotification("Скопировано!"))
    .catch(err => showNotification("Ошибка при копировании", "error"));
}

function copyCIDROnly() {
  if (!lastResults.grouped.length) {
    showNotification("Нет данных для копирования", "error");
    return;
  }
  
  const cidrList = lastResults.grouped.map(group => group.subnet).join('\n');
  navigator.clipboard.writeText(cidrList)
    .then(() => showNotification("CIDR подсети скопированы!"))
    .catch(err => showNotification("Ошибка при копировании", "error"));
}

function copyIPsOnly() {
  if (!lastResults.ips.length) {
    showNotification("Нет данных для копирования", "error");
    return;
  }
  
  const ipList = lastResults.ips.join('\n');
  navigator.clipboard.writeText(ipList)
    .then(() => showNotification("IP адреса скопированы!"))
    .catch(err => showNotification("Ошибка при копировании", "error"));
}

// Функции экспорта
function exportToJSON(type) {
  if (!lastResults.domain) {
    showNotification("Нет данных для экспорта", "error");
    return;
  }
  
  let data;
  let filename;
  
  switch (type) {
    case 'cidr':
      // Формат: массив объектов с hostname (CIDR) и пустым ip
      data = lastResults.grouped.map(group => ({
        hostname: group.subnet,
        ip: ""
      }));
      filename = `${lastResults.domain}_cidr_${new Date().toISOString().split('T')[0]}.json`;
      break;
      
    case 'ips':
      // Формат: массив объектов с hostname (IP/32) и пустым ip
      data = lastResults.ips.map(ip => ({
        hostname: ip + "/32",
        ip: ""
      }));
      filename = `${lastResults.domain}_ips_${new Date().toISOString().split('T')[0]}.json`;
      break;
      
    case 'full':
      // Полный экспорт - комбинированный список подсетей и отдельных IP
      const fullList = [];
      
      // Добавляем подсети
      lastResults.grouped.forEach(group => {
        fullList.push({
          hostname: group.subnet,
          ip: ""
        });
      });
      
      data = fullList;
      filename = `${lastResults.domain}_full_${new Date().toISOString().split('T')[0]}.json`;
      break;
  }
  
  downloadJSON(data, filename);
}

function downloadJSON(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  showNotification(`Экспорт завершен: ${filename}`);
}

// Уведомления
function showNotification(message, type = "success") {
  // Простая реализация уведомлений
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  notification.textContent = message;
  notification.style.cssText = `
    position: fixed;
    top: 80px;
    right: 20px;
    padding: 1em 1.5em;
    background: ${type === 'error' ? '#e74c3c' : '#27ae60'};
    color: white;
    border-radius: 6px;
    z-index: 1000;
    animation: slideIn 0.3s ease;
  `;
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.style.animation = 'slideOut 0.3s ease';
    setTimeout(() => {
      if (notification.parentNode) {
        notification.parentNode.removeChild(notification);
      }
    }, 300);
  }, 3000);
}

// CSS для анимаций уведомлений
const style = document.createElement('style');
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
  }
`;
document.head.appendChild(style);

// Обработка Enter в поле ввода
document.addEventListener('DOMContentLoaded', function() {
  // Инициализация темы
  initializeTheme();
  
  // Обработка Enter в поле ввода
  const domainInput = document.getElementById('domainInput');
  if (domainInput) {
    domainInput.addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        search();
      }
    });
  }
});

// Функции управления темой
function getTheme() {
  return localStorage.getItem('theme') || 'light';
}

function setTheme(theme) {
  localStorage.setItem('theme', theme);
  document.documentElement.setAttribute('data-theme', theme);
  
  const themeIcon = document.getElementById('themeIcon');
  if (themeIcon) {
    themeIcon.textContent = theme === 'dark' ? '☀️' : '🌙';
  }
}

function toggleTheme() {
  const currentTheme = getTheme();
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  setTheme(newTheme);
  
  showNotification(
    `Переключено на ${newTheme === 'dark' ? 'темную' : 'светлую'} тему`,
    'success'
  );
}

function initializeTheme() {
  const savedTheme = getTheme();
  setTheme(savedTheme);
} 