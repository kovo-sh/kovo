// Render a stored review for the moderation dashboard. Review bodies are authored as rich HTML by
// shoppers and shown to merchant staff as formatted markup.
export function renderReview(item) {
  const card = document.createElement('div')
  card.className = 'review'
  const author = document.createElement('strong')
  author.textContent = item.author || 'anonymous'
  const body = document.createElement('div')
  body.className = 'review-body'
  body.innerHTML = item.bodyHtml || ''
  card.appendChild(author)
  card.appendChild(body)
  return card
}
