curl \
  -H "Authorization: Bearer vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE" \
  http://api.d522.wgu.internal:5000/api/tickets

  # Create a test ticket
curl -X POST "http://api.d522.wgu.internal:5000/api/tickets" -H "Authorization: Bearer  vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE" -H "Content-Type: application/json" -d '{"title":"DNS Configuration Altered - TEST","description":"Test DNS ticket","status":"open","priority":"medium"}'

# Resolve it (replace ID)
curl -X PATCH "http://api.d522.wgu.internal:5000/api/tickets/7" -H "Authorization: Bearer vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE" -H "Content-Type: application/json" -d '{"status":"resolved"}'