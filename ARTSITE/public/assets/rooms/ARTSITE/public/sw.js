/* ISMAILTENNI ART - small offline helper. Pictures are kept for fast repeat visits. Pages always try the network first. */
var V='iart-v1';
self.addEventListener('install',function(e){self.skipWaiting()});
self.addEventListener('activate',function(e){e.waitUntil(caches.keys().then(function(k){return Promise.all(k.filter(function(x){return x!==V}).map(function(x){return caches.delete(x)}))}).then(function(){return self.clients.claim()}))});
self.addEventListener('fetch',function(e){
  var r=e.request,u=new URL(r.url);
  if(r.method!=='GET'||u.origin!==location.origin)return;
  if(u.pathname.indexOf('/api/')===0&&u.pathname.indexOf('/api/media/')!==0)return;
  if(r.mode==='navigate'){
    e.respondWith(fetch(r).then(function(res){if(res.ok&&(u.pathname==='/'||u.pathname==='/index.html')){var c=res.clone();caches.open(V).then(function(h){h.put('/',c)})}return res}).catch(function(){return caches.match('/').then(function(x){return x||Response.error()})}));
    return;
  }
  if(/^\/(assets|icons)\//.test(u.pathname)||u.pathname.indexOf('/api/media/')===0||/\.(jpg|webp|png|css|js)$/.test(u.pathname)){
    e.respondWith(caches.open(V).then(function(h){return h.match(r).then(function(m){
      var f=fetch(r).then(function(res){if(res.ok)h.put(r,res.clone());return res}).catch(function(){return m});
      return m||f})}));
  }
});
