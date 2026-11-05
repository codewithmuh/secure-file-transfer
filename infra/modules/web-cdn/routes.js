// CloudFront Function, viewer request (ADR-0008): app routes, paths whose last segment has no file extension, serve
// /index.html. Files keep their own path, so a missing asset stays a 404.
function handler(event) {
  var request = event.request;
  var last = request.uri.substring(request.uri.lastIndexOf('/') + 1);

  if (last.indexOf('.') === -1) {
    request.uri = '/index.html';
  }

  return request;
}
