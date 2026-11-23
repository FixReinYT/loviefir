import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, scrypt, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdir, readFile, unlink, rename, stat } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import path from 'node:path';

const dir=path.resolve(process.env.DATA_DIR||'data'); await mkdir(dir,{recursive:true});
const db=new DatabaseSync(path.join(dir,'site.sqlite'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT COLLATE NOCASE UNIQUE,salt TEXT,hash BLOB);
CREATE TABLE IF NOT EXISTS sessions(key TEXT PRIMARY KEY,uid INTEGER,expires INTEGER);
CREATE TABLE IF NOT EXISTS videos(id TEXT PRIMARY KEY,uid INTEGER,title TEXT,topic TEXT,mime TEXT,created INTEGER);
CREATE TABLE IF NOT EXISTS follows(uid INTEGER,author INTEGER,PRIMARY KEY(uid,author));
CREATE TABLE IF NOT EXISTS votes(uid INTEGER,video TEXT,score INTEGER,PRIMARY KEY(uid,video));
CREATE TABLE IF NOT EXISTS playlists(id TEXT PRIMARY KEY,uid INTEGER,title TEXT,description TEXT,created INTEGER);
CREATE TABLE IF NOT EXISTS playlist_videos(playlist TEXT,video TEXT,PRIMARY KEY(playlist,video));
CREATE TABLE IF NOT EXISTS views(id INTEGER PRIMARY KEY,video TEXT,uid INTEGER,created INTEGER);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY,video TEXT,uid INTEGER,text TEXT,created INTEGER);`);
function addColumn(table,name,type){try{db.exec('ALTER TABLE '+table+' ADD COLUMN '+name+' '+type)}catch(e){if(!String(e.message).includes('duplicate column'))throw e}}
for(const [n,t] of [['handle','TEXT'],['description','TEXT NOT NULL DEFAULT ""'],['avatar','TEXT'],['banner','TEXT'],['links','TEXT NOT NULL DEFAULT "[]"']])addColumn('users',n,t);
for(const [n,t] of [['description','TEXT NOT NULL DEFAULT ""'],['thumbnail','TEXT'],['tags','TEXT NOT NULL DEFAULT "[]"'],['visibility','TEXT NOT NULL DEFAULT "public"'],['audience','TEXT NOT NULL DEFAULT "general"'],['comments_enabled','INTEGER NOT NULL DEFAULT 1'],['views','INTEGER NOT NULL DEFAULT 0']])addColumn('videos',n,t);
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS users_handle_unique ON users(handle) WHERE handle IS NOT NULL AND handle<>''");
const topics=['Анимация','Игры','Музыка','Образование','Путешествия','Развлечения','Другое'];
const derive=promisify(scrypt),digest=v=>createHash('sha256').update(v).digest('hex');
const fail=(code,message)=>{throw Object.assign(new Error(message),{code})};
async function jsonBody(req,limit=65536){const chunks=[];let size=0;for await(const c of req){size+=c.length;if(size>limit)fail(413,'Слишком много данных');chunks.push(c)}try{return JSON.parse(Buffer.concat(chunks).toString())||{}}catch{fail(400,'Некорректный JSON')}}
const html=await readFile(new URL('./index.html',import.meta.url)),attempts=new Map();
const cleanup=setInterval(()=>{for(const [ip,e] of attempts)if(e.until<Date.now())attempts.delete(ip);db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now())},600000);cleanup.unref();
function publicUser(id){return db.prepare("SELECT id,name,COALESCE(handle,'') handle,description,avatar,banner,links FROM users WHERE id=?").get(id)}
function videoRow(v){return {...v,tags:JSON.parse(v.tags||'[]'),comments_enabled:!!v.comments_enabled}}
http.createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,'http://localhost'),route=url.pathname,method=req.method;
  const send=(v,s=200)=>{res.writeHead(s,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(v))};
  res.setHeader('X-Content-Type-Options','nosniff');
  if(method==='POST'&&req.headers.origin&&new URL(req.headers.origin).host!==req.headers.host)fail(403,'Недопустимый источник');
  const token=req.headers.cookie?.match(/(?:^|; *)sid=([a-f0-9]{64})(?:;|$)/)?.[1]||'';
  const user=db.prepare('SELECT u.id,u.name FROM users u JOIN sessions s ON s.uid=u.id WHERE s.key=? AND s.expires>?').get(digest(token),Date.now());
  if(method==='GET'&&route==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(html)}
  if(method==='GET'&&route==='/api/me')return send(user?publicUser(user.id):null);
  if(method==='POST'&&['/api/register','/api/login'].includes(route)){
   const ip=req.socket.remoteAddress,now=Date.now();let a=attempts.get(ip);if(!a||a.until<now){a={count:0,until:now+600000};attempts.set(ip,a)}if(++a.count>40)fail(429,'Попробуйте позже');
   const {name,password}=await jsonBody(req);if(typeof name!=='string'||!name.trim()||name.length>60||typeof password!=='string'||password.length<8||password.length>200)fail(400,'Введите имя и пароль (не менее 8 символов)');
   let account=db.prepare('SELECT * FROM users WHERE name=?').get(name.trim());
   if(route.endsWith('register')){const salt=randomBytes(16).toString('hex'),hash=await derive(password,salt,64);const r=db.prepare('INSERT OR IGNORE INTO users(name,handle,salt,hash) VALUES(?,?,?,?)').run(name.trim(),name.trim().toLowerCase().replace(/[^a-z0-9_]/g,'').slice(0,24)||('user'+Date.now()),salt,hash);if(!r.changes)fail(409,'Имя занято');account={id:r.lastInsertRowid}}
   else if(!account||!timingSafeEqual(account.hash,await derive(password,account.salt,64)))fail(401,'Проверьте имя и пароль');
   const sid=randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(digest(sid),account.id,now+2592000000);
   res.setHeader('Set-Cookie','sid='+sid+'; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000'+(process.env.SECURE_COOKIE==='1'?'; Secure':''));return send({ok:true});
  }
  if(method==='GET'&&route==='/api/video'){
   const id=url.searchParams.get('id'),v=db.prepare("SELECT v.*,u.name,u.handle,u.avatar FROM videos v JOIN users u ON u.id=v.uid WHERE v.id=? AND (v.visibility IN ('public','unlisted') OR v.uid=?)").get(id,user?.id||0);
   if(!v)fail(404,'Видео не найдено');return send(videoRow(v));
  }
  if(method==='GET'&&route==='/api/comments'){
   const id=url.searchParams.get('video'),v=db.prepare("SELECT comments_enabled FROM videos WHERE id=? AND visibility IN ('public','unlisted')").get(id);
   if(!v||!v.comments_enabled)return send([]);
   return send(db.prepare('SELECT c.id,c.text,c.created,u.name,u.handle,u.avatar FROM comments c JOIN users u ON u.id=c.uid WHERE c.video=? ORDER BY c.created DESC LIMIT 100').all(id));
  }
  if(method==='GET'&&route==='/api/playlist'){
   const id=url.searchParams.get('id'),p=db.prepare('SELECT id,uid,title,description,created FROM playlists WHERE id=?').get(id);
   if(!p)fail(404,'Плейлист не найден');
   const videos=db.prepare("SELECT v.*,u.name,u.handle,u.avatar FROM playlist_videos pv JOIN videos v ON v.id=pv.video JOIN users u ON u.id=v.uid WHERE pv.playlist=? AND (v.visibility IN ('public','unlisted') OR v.uid=?) ORDER BY v.created DESC").all(id,user?.id||0).map(videoRow);
   return send({...p,videos});
  }
  if(method==='GET'&&route==='/api/playlists'){
   const uid=Number(url.searchParams.get('uid'))||user?.id||0;
   return send(db.prepare('SELECT p.id,p.title,p.description,p.created,(SELECT COUNT(*) FROM playlist_videos pv WHERE pv.playlist=p.id) count FROM playlists p WHERE p.uid=? ORDER BY p.created DESC').all(uid));
  }
  if(method==='GET'&&route==='/api/subscriptions'){
   if(!user)return send([]);
   const rows=db.prepare(`SELECT u.id,u.name,COALESCE(u.handle,'') handle,u.description,u.avatar,u.banner,
    (SELECT COUNT(*) FROM follows f2 WHERE f2.author=u.id) followers,
    (SELECT COUNT(*) FROM videos v WHERE v.uid=u.id AND v.visibility='public') videos,
    (SELECT MAX(v.created) FROM videos v WHERE v.uid=u.id AND v.visibility='public') latest
    FROM follows f JOIN users u ON u.id=f.author WHERE f.uid=? ORDER BY u.name COLLATE NOCASE`).all(user.id);
   return send(rows);
  }
  if(method==='GET'&&route==='/api/channel'){
   const id=Number(url.searchParams.get('id'));if(!Number.isSafeInteger(id)||id<1)fail(400,'Некорректный канал');
   const channel=publicUser(id);if(!channel)fail(404,'Канал не найден');
   const followers=db.prepare('SELECT COUNT(*) n FROM follows WHERE author=?').get(id).n,following=db.prepare('SELECT COUNT(*) n FROM follows WHERE uid=?').get(id).n;
   const subscribed=!!(user&&db.prepare('SELECT 1 FROM follows WHERE uid=? AND author=?').get(user.id,id));
   const videos=db.prepare("SELECT v.*,u.name,u.handle,u.avatar FROM videos v JOIN users u ON u.id=v.uid WHERE v.uid=? AND (v.visibility='public' OR ?=v.uid) ORDER BY v.created DESC").all(id,user?.id||0).map(videoRow);
   return send({...channel,followers,following,subscribed,isMe:user?.id===id,videos});
  }
  if(method==='GET'&&route==='/api/videos'){
   const uid=user?.id||0,mode=url.searchParams.get('mode'),q=(url.searchParams.get('q')||'').slice(0,100),topic=url.searchParams.get('topic')||'';
   const rows=db.prepare(`WITH prefs AS (SELECT v.topic,SUM(b.score) weight FROM votes b JOIN videos v ON v.id=b.video WHERE b.uid=? GROUP BY v.topic)
   SELECT v.*,u.name,u.handle,u.avatar,f.uid IS NOT NULL following,COALESCE(p.weight,0) weight,COALESCE(b.score,0) score
   FROM videos v JOIN users u ON u.id=v.uid LEFT JOIN follows f ON f.author=u.id AND f.uid=? LEFT JOIN prefs p ON p.topic=v.topic LEFT JOIN votes b ON b.video=v.id AND b.uid=?
   WHERE (v.visibility='public' OR v.uid=?) AND (?=0 OR f.uid IS NOT NULL) AND (?='' OR v.topic=?) AND (instr(lower(v.title),lower(?)) OR instr(lower(v.description),lower(?)) OR instr(lower(u.name),lower(?)) OR instr(lower(v.tags),lower(?)))
   ORDER BY CASE WHEN ?=1 THEN COALESCE(p.weight,0) ELSE 0 END DESC,v.created DESC LIMIT 200`).all(uid,uid,uid,uid,Number(mode==='subs'),topic,topic,q,q,q,q,Number(mode!=='subs'));
   return send(rows.map(videoRow));
  }
  if(route.startsWith('/media/')&&['GET','HEAD'].includes(method)){
   const id=path.basename(route.slice(7)),v=db.prepare('SELECT mime FROM videos WHERE id=?').get(id);if(!v)fail(404,'Видео не найдено');
   const file=path.join(dir,id),{size}=await stat(file);let start=0,end=size-1;const range=req.headers.range;
   if(range){const m=/^bytes=(\\d*)-(\\d*)$/.exec(range);if(m&&(m[1]||m[2])){start=m[1]?Number(m[1]):Math.max(0,size-Number(m[2]));end=m[1]&&m[2]?Math.min(end,Number(m[2])):end}if(!m||!(m[1]||m[2])||start>end||start>=size){res.writeHead(416,{'Content-Range':'bytes */'+size});return res.end()}res.setHeader('Content-Range',`bytes \${start}-\${end}/\${size}`)}
   res.writeHead(range?206:200,{'Accept-Ranges':'bytes','Content-Type':v.mime,'Content-Length':end-start+1});if(method==='HEAD')return res.end();await pipeline(createReadStream(file,{start,end}),res);return;
  }
  if(route.startsWith('/asset/')&&['GET','HEAD'].includes(method)){
   const id=path.basename(route.slice(7)),file=path.join(dir,id);const {size}=await stat(file);const ext=path.extname(id).toLowerCase(),mime=({'.jpg':'image/jpeg','.jpeg':'image/jpeg','.png':'image/png','.webp':'image/webp'})[ext]||'application/octet-stream';
   res.writeHead(200,{'Content-Type':mime,'Content-Length':size,'Cache-Control':'public, max-age=86400'});if(method==='HEAD')return res.end();await pipeline(createReadStream(file),res);return;
  }
  if(method!=='POST'&&method!=='PUT'&&method!=='DELETE')fail(404,'Не найдено');
  if(route==='/api/logout'){if(method!=='POST')fail(405,'Метод не поддерживается');db.prepare('DELETE FROM sessions WHERE key=?').run(digest(token));res.setHeader('Set-Cookie','sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');return send({ok:true})}
  if(!user)fail(401,'Войдите в ЛовиЭфир');
  if(route==='/api/profile'&&method==='POST'){
   const b=await jsonBody(req);const name=String(b.name||'').trim(),handle=String(b.handle||'').trim().replace(/^@/,''),description=String(b.description||'').slice(0,2000),links=Array.isArray(b.links)?b.links.slice(0,8).map(x=>String(x).slice(0,300)): [];
   if(!name||name.length>60)fail(400,'Название канала: от 1 до 60 символов');
   if(!/^[a-zA-Z0-9_]{3,24}$/.test(handle))fail(400,'Псевдоним: 3–24 символа, латиница, цифры и _');
   if(db.prepare('SELECT 1 FROM users WHERE handle=? AND id<>?').get(handle,user.id))fail(409,'Этот псевдоним уже занят');
   db.prepare('UPDATE users SET name=?,handle=?,description=?,links=? WHERE id=?').run(name,handle,description,JSON.stringify(links),user.id);return send(publicUser(user.id));
  }
  if(route==='/api/profile-image'&&method==='POST'){
   const kind=url.searchParams.get('kind');if(!['avatar','banner'].includes(kind))fail(400,'Неизвестный тип изображения');
   const mime=req.headers['content-type'];if(!['image/jpeg','image/png','image/webp'].includes(mime))fail(400,'Используй JPG, PNG или WebP');
   const id=randomUUID()+({ 'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp'}[mime]),tmp=path.join(dir,id+'.part'),file=path.join(dir,id);let size=0;
   try{const lim=new Transform({transform(c,e,cb){size+=c.length;cb(size>(kind==='avatar'?5:10)*1024*1024?new Error('Файл слишком большой'):null,c)}});await pipeline(req,lim,createWriteStream(tmp,{flags:'wx'}));if(!size)fail(400,'Пустой файл');await rename(tmp,file);db.prepare('UPDATE users SET '+kind+'=? WHERE id=?').run(id,user.id)}catch(e){await Promise.allSettled([unlink(tmp),unlink(file)]);throw e}
   return send({url:'/asset/'+id});
  }
  if(route==='/api/upload'&&method==='POST'){
   const title=(url.searchParams.get('title')||'').trim(),topic=url.searchParams.get('topic'),mime=req.headers['content-type'];
   if(!title||title.length>120||!topics.includes(topic)||!['video/mp4','video/webm'].includes(mime))fail(400,'Укажи название, категорию и видео MP4/WebM');
   const id=randomUUID(),file=path.join(dir,id),tmp=file+'.part';let size=0;
   try{const lim=new Transform({transform(c,e,cb){size+=c.length;cb(size>512*1024*1024?new Error('Максимум 512 МБ'):null,c)}});await pipeline(req,lim,createWriteStream(tmp,{flags:'wx'}));if(!size)fail(400,'Пустой файл');await rename(tmp,file);
    const description=(url.searchParams.get('description')||'').slice(0,5000),tags=(url.searchParams.get('tags')||'').split(',').map(x=>x.trim()).filter(Boolean).slice(0,20),visibility=['public','unlisted','private'].includes(url.searchParams.get('visibility'))?url.searchParams.get('visibility'):'public',audience=url.searchParams.get('audience')==='kids'?'kids':'general',comments=url.searchParams.get('comments')!=='0';
    db.prepare('INSERT INTO videos(id,uid,title,topic,mime,created,description,tags,visibility,audience,comments_enabled) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(id,user.id,title,topic,mime,Date.now(),description,JSON.stringify(tags),visibility,audience,Number(comments));
   }catch(e){await Promise.allSettled([unlink(tmp),unlink(file)]);throw e}return send({id},201);
  }
  if(route==='/api/video'&&method==='POST'){
   const b=await jsonBody(req);const v=db.prepare('SELECT * FROM videos WHERE id=? AND uid=?').get(b.id,user.id);if(!v)fail(404,'Видео не найдено');
   const title=String(b.title||'').trim(),topic=String(b.topic||''),visibility=['public','unlisted','private'].includes(b.visibility)?b.visibility:'public';
   if(!title||title.length>120||!topics.includes(topic))fail(400,'Проверь название и категорию');
   db.prepare('UPDATE videos SET title=?,topic=?,description=?,tags=?,visibility=?,audience=?,comments_enabled=? WHERE id=? AND uid=?').run(title,topic,String(b.description||'').slice(0,5000),JSON.stringify(Array.isArray(b.tags)?b.tags.slice(0,20):[]),visibility,b.audience==='kids'?'kids':'general',b.comments_enabled===false?0:1,b.id,user.id);return send({ok:true});
  }
  if(route==='/api/video-delete'&&method==='POST'){const b=await jsonBody(req);const v=db.prepare('SELECT id FROM videos WHERE id=? AND uid=?').get(b.id,user.id);if(!v)fail(404,'Видео не найдено');db.prepare('DELETE FROM playlist_videos WHERE video=?').run(b.id);db.prepare('DELETE FROM votes WHERE video=?').run(b.id);db.prepare('DELETE FROM comments WHERE video=?').run(b.id);db.prepare('DELETE FROM videos WHERE id=?').run(b.id);await unlink(path.join(dir,b.id)).catch(()=>{});return send({ok:true})}
  if(route==='/api/thumbnail'&&method==='POST'){
   const id=url.searchParams.get('id'),v=db.prepare('SELECT id FROM videos WHERE id=? AND uid=?').get(id,user.id);if(!v)fail(404,'Видео не найдено');const mime=req.headers['content-type'];if(!['image/jpeg','image/png','image/webp'].includes(mime))fail(400,'Нужна картинка JPG, PNG или WebP');const asset=randomUUID()+({ 'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp'}[mime]),tmp=path.join(dir,asset+'.part');let size=0;try{const lim=new Transform({transform(c,e,cb){size+=c.length;cb(size>8*1024*1024?new Error('Максимум 8 МБ'):null,c)}});await pipeline(req,lim,createWriteStream(tmp,{flags:'wx'}));await rename(tmp,path.join(dir,asset));db.prepare('UPDATE videos SET thumbnail=? WHERE id=?').run(asset,id)}catch(e){await unlink(tmp).catch(()=>{});throw e}return send({url:'/asset/'+asset});
  }
  if(route==='/api/follow'){const b=await jsonBody(req);if(!Number.isInteger(b.author)||b.author===user.id||!db.prepare('SELECT 1 FROM users WHERE id=?').get(b.author))fail(404,'Нет такого канала');if(b.enabled)db.prepare('INSERT OR IGNORE INTO follows VALUES(?,?)').run(user.id,b.author);else db.prepare('DELETE FROM follows WHERE uid=? AND author=?').run(user.id,b.author);return send({ok:true})}
  if(route==='/api/vote'){const b=await jsonBody(req);if(![-1,0,1].includes(b.score)||!db.prepare('SELECT 1 FROM videos WHERE id=?').get(b.video))fail(400,'Некорректная оценка');db.prepare('INSERT OR REPLACE INTO votes VALUES(?,?,?)').run(user.id,b.video,b.score);return send({ok:true})}
  if(route==='/api/view'){const b=await jsonBody(req);const v=db.prepare("SELECT id FROM videos WHERE id=? AND (visibility='public' OR uid=?)").get(b.video,user.id);if(!v)fail(404,'Видео не найдено');db.prepare('INSERT INTO views(video,uid,created) VALUES(?,?,?)').run(b.video,user.id,Date.now());db.prepare('UPDATE videos SET views=views+1 WHERE id=?').run(b.video);return send({ok:true})}
  if(route==='/api/comments'&&method==='POST'){const b=await jsonBody(req);const v=db.prepare('SELECT comments_enabled FROM videos WHERE id=?').get(b.video);if(!v||!v.comments_enabled)fail(403,'Комментарии отключены');const text=String(b.text||'').trim();if(!text||text.length>2000)fail(400,'Комментарий должен содержать от 1 до 2000 символов');db.prepare('INSERT INTO comments(video,uid,text,created) VALUES(?,?,?,?)').run(b.video,user.id,text,Date.now());return send({ok:true},201)}
  if(route==='/api/playlist'&&method==='POST'){const b=await jsonBody(req);const title=String(b.title||'').trim();if(!title||title.length>100)fail(400,'Название плейлиста обязательно');const id=randomUUID();db.prepare('INSERT INTO playlists VALUES(?,?,?,?,?)').run(id,user.id,title,String(b.description||'').slice(0,1000),Date.now());return send({id},201)}
  if(route==='/api/playlist-add'&&method==='POST'){const b=await jsonBody(req);if(!db.prepare('SELECT 1 FROM playlists WHERE id=? AND uid=?').get(b.playlist,user.id)||!db.prepare('SELECT 1 FROM videos WHERE id=? AND (uid=? OR visibility="public")').get(b.video,user.id))fail(404,'Плейлист или видео не найдено');db.prepare('INSERT OR IGNORE INTO playlist_videos VALUES(?,?)').run(b.playlist,b.video);return send({ok:true})}
  if(route==='/api/stats'&&method==='GET'){const own=db.prepare('SELECT COUNT(*) videos,COALESCE(SUM(views),0) views FROM videos WHERE uid=?').get(user.id),followers=db.prepare('SELECT COUNT(*) n FROM follows WHERE author=?').get(user.id).n;return send({...own,followers,comments:db.prepare('SELECT COUNT(*) n FROM comments c JOIN videos v ON v.id=c.video WHERE v.uid=?').get(user.id).n})}
  fail(404,'Не найдено');
 }catch(err){if(res.headersSent||res.destroyed)return;const code=Number.isInteger(err.code)?err.code:500;res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify({error:code===500?'Ошибка сервера':err.message}));if(code===500)console.error(err)}
}).listen(Number(process.env.PORT||8080),process.env.HOST||'0.0.0.0');
