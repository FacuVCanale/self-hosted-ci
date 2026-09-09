'use strict';

const path = require('node:path');

const fragmentMono = path.join(__dirname, 'fonts', 'FragmentMono-Regular.ttf');
const geist = path.join(__dirname, 'fonts', 'Geist[wght].ttf');
const geistMono = path.join(__dirname, 'fonts', 'GeistMono[wght].ttf');

module.exports = Object.freeze({
  'https://fonts.googleapis.com/css2?family=Fragment+Mono:wght@400&display=swap':
    `/* latin */
@font-face {
  font-family: 'Fragment Mono';
  font-style: normal;
  font-display: swap;
  font-weight: 400;
  src: url(${fragmentMono}) format('truetype');
}`,
  'https://fonts.googleapis.com/css2?family=Geist:wght@100..900&display=swap':
    `/* latin */
@font-face {
  font-family: 'Geist';
  font-style: normal;
  font-display: swap;
  font-weight: 100 900;
  src: url(${geist}) format('truetype');
}`,
  'https://fonts.googleapis.com/css2?family=Geist+Mono:wght@100..900&display=swap':
    `/* latin */
@font-face {
  font-family: 'Geist Mono';
  font-style: normal;
  font-display: swap;
  font-weight: 100 900;
  src: url(${geistMono}) format('truetype');
}`,
});
