import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, randomUUID, scrypt, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdir, readFile, unlink, rename, stat } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import path from 'node:path';

const dir = path.resolve(process.env.DATA_DIR || 'data');
await mkdir(dir,{recursive:true});
const db = new DatabaseSync(path.join(dir,'site.sqlite'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT COLLATE NOCASE UNIQUE,salt TEXT,hash BLOB);
CREATE TABLE IF NOT EXISTS sessions(key TEXT PRIMARY KEY,uid INTEGER,expires INTEGER);
CREATE TABLE IF NOT EXISTS videos(id TEXT PRIMARY KEY,uid INTEGER,title TEXT,topic TEXT,mime TEXT,created INTEGER);
CREATE TABLE IF NOT EXISTS follows(uid INTEGER, author INTEGER,PRIMARY KEY(uid,author));
CREATE TABLE IF NOT EXISTS votes(uid INTEGER,video TEXT,score INTEGER,PRIMARY KEY(uid,video));`);
const topics=['Анимация','Игры','Музыка','Другое'];
const derive=promisify(scrypt);
const digest=value=>createHash('sha256').update(value).digest('hex');
const fail=(code,message)=>{throw Object.assign(new Error(message),{code})};
async function jsonBody(req){
 const chunks=[];let size=0;
 for await(const chunk of req){size+=chunk.length;if(size>8192)fail(413,'Слишком много данных');chunks.push(chunk)}
 try{return JSON.parse(Buffer.concat(chunks).toString())||{}}catch{fail(400,'Некорректный JSON')}
}
const html=await readFile(new URL('./index.html',import.meta.url));
const attempts=new Map();
const cleanup=setInterval(()=>{for(const [ip,entry] of attempts)if(entry.until<Date.now())attempts.delete(ip);db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now())},600000);cleanup.unref();
http.createServer(async(req,res)=>{
 try{
  const url=new URL(req.url,'http://localhost'),route=url.pathname,method=req.method;
  const send=(value,status=200)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(value))};
  res.setHeader('X-Content-Type-Options','nosniff');
  if(method==='POST'&&req.headers.origin&&new URL(req.headers.origin).host!==req.headers.host)fail(403,'Недопустимый источник');
  const token=req.headers.cookie?.match(/(?:^|; *)sid=([a-f0-9]{64})(?:;|$)/)?.[1]||'';
  const user=db.prepare('SELECT u.id,u.name FROM users u JOIN sessions s ON s.uid=u.id WHERE s.key=? AND s.expires>?').get(digest(token),Date.now());
  if(method==='GET'&&route==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(html)}
  if(method==='GET'&&route==='/api/me')return send(user||null);
  if(method==='GET'&&route==='/api/channel'){
   const id=Number(url.searchParams.get('id'));
   if(!Number.isSafeInteger(id)||id<1)fail(400,'Некорректный канал');
   const channel=db.prepare('SELECT id,name FROM users WHERE id=?').get(id);
   if(!channel)fail(404,'Канал не найден');
   const followers=db.prepare('SELECT COUNT(*) n FROM follows WHERE author=?').get(id).n;
   const following=db.prepare('SELECT COUNT(*) n FROM follows WHERE uid=?').get(id).n;
   const subscribed=!!(user&&db.prepare('SELECT 1 FROM follows WHERE uid=? AND author=?').get(user.id,id));
   const videos=db.prepare('SELECT id,uid,title,topic,mime,created FROM videos WHERE uid=? ORDER BY created DESC').all(id);
   return send({...channel,followers,following,subscribed,isMe:user?.id===id,videos});
  }
  if(method==='POST'&&['/api/register','/api/login'].includes(route)){
   const ip=req.socket.remoteAddress,now=Date.now();let entry=attempts.get(ip);
   if(!entry||entry.until<now){entry={count:0,until:now+600000};attempts.set(ip,entry)}
   if(++entry.count>40)fail(429,'Попробуйте позже');
   const {name,password}=await jsonBody(req);
   if(typeof name!=='string'||!name.trim()||name.length>60||typeof password!=='string'||password.length<8||password.length>200)fail(400,'Введите имя и пароль от 8 до 200 символов');
   let account=db.prepare('SELECT * FROM users WHERE name=?').get(name.trim());
   if(route.endsWith('register')){
    const salt=randomBytes(16).toString('hex'),hash=await derive(password,salt,64);
    const result=db.prepare('INSERT OR IGNORE INTO users(name,salt,hash) VALUES(?,?,?)').run(name.trim(),salt,hash);
    if(!result.changes)fail(409,'Имя занято');account={id:result.lastInsertRowid};
   }else if(!account||!timingSafeEqual(account.hash,await derive(password,account.salt,64)))fail(401,'Проверьте имя и пароль');
   const sid=randomBytes(32).toString('hex');
   db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(digest(sid),account.id,now+2592000000);
   res.setHeader('Set-Cookie','sid='+sid+'; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000'+(process.env.SECURE_COOKIE==='1'?'; Secure':''));
   return send({ok:true});
  }
  if(method==='GET'&&route==='/api/videos'){
   const uid=user?.id||0,mode=url.searchParams.get('mode'),query=url.searchParams.get('q')||'';
   return send(db.prepare(`WITH prefs AS (SELECT v.topic,SUM(b.score) weight FROM votes b JOIN videos v ON v.id=b.video WHERE b.uid=? GROUP BY v.topic)
   SELECT v.id,v.uid,v.title,v.topic,v.mime,v.created,u.name,f.uid IS NOT NULL following,COALESCE(p.weight,0) weight,COALESCE(b.score,0) score
   FROM videos v JOIN users u ON u.id=v.uid LEFT JOIN follows f ON f.author=u.id AND f.uid=? LEFT JOIN prefs p ON p.topic=v.topic
   LEFT JOIN votes b ON b.video=v.id AND b.uid=?
   WHERE (?=0 OR f.uid IS NOT NULL) AND (instr(lower(v.title),lower(?)) OR instr(lower(u.name),lower(?)))
   ORDER BY CASE WHEN ?=1 THEN COALESCE(p.weight,0) ELSE 0 END DESC,v.created DESC,v.rowid DESC`).all(uid,uid,uid,Number(mode==='subs'),query,query,Number(mode!=='subs')));
  }
  if(['GET','HEAD'].includes(method)&&route.startsWith('/media/')){
   const id=route.slice(7),v=db.prepare('SELECT mime FROM videos WHERE id=?').get(id);
   if(!v)fail(404,'Видео не найдено');
   const file=path.join(dir,id),{size}=await stat(file);let start=0,end=size-1;const range=req.headers.range;
   if(range){const m=/^bytes=(\\d*)-(\\d*)$/.exec(range);
    if(m&&(m[1]||m[2])){start=m[1]?Number(m[1]):Math.max(0,size-Number(m[2]));end=m[1]&&m[2]?Math.min(end,Number(m[2])):end}
    if(!m||!(m[1]||m[2])||start>end||start>=size){res.writeHead(416,{'Content-Range':'bytes */'+size});return res.end()}
    res.setHeader('Content-Range',`bytes ${start}-${end}/${size}`);
   }
   res.writeHead(range?206:200,{'Accept-Ranges':'bytes','Content-Type':v.mime,'Content-Length':end-start+1});
   if(method==='HEAD')return res.end();await pipeline(createReadStream(file,{start,end}),res);return;
  }
  if(method!=='POST')fail(404,'Не найдено');if(!user)fail(401,'Войдите в канал');
  if(route==='/api/logout'){db.prepare('DELETE FROM sessions WHERE key=?').run(digest(token));res.setHeader('Set-Cookie','sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');return send({ok:true})}
  if(route==='/api/upload'){
   const title=url.searchParams.get('title')?.trim(),topic=url.searchParams.get('topic'),mime=req.headers['content-type'];
   if(!title||title.length>120||!topics.includes(topic)||!['video/mp4','video/webm'].includes(mime))fail(400,'Нужны название, тема и видео MP4 или WebM');
   const limit=256*1024*1024;if(Number(req.headers['content-length'])>limit)fail(413,'Максимум 256 МБ');
   const id=randomUUID(),file=path.join(dir,id),tmp=file+'.part';let size=0;
   try{const limiter=new Transform({transform(chunk,enc,cb){size+=chunk.length;cb(size>limit?Object.assign(new Error('Максимум 256 МБ'),{code:413}):null,chunk)}});
    await pipeline(req,limiter,createWriteStream(tmp,{flags:'wx'}));if(!size)fail(400,'Пустой файл');
    await rename(tmp,file);db.prepare('INSERT INTO videos VALUES(?,?,?,?,?,?)').run(id,user.id,title,topic,mime,Date.now());
   }catch(err){await Promise.allSettled([unlink(tmp),unlink(file)]);throw err}
   return send({id},201);
  }
  const body=await jsonBody(req);
  if(route==='/api/follow'){
   if(!Number.isInteger(body.author)||body.author===user.id||!db.prepare('SELECT 1 FROM users WHERE id=?').get(body.author))fail(404,'Нет такого канала');
   if(body.enabled)db.prepare('INSERT OR IGNORE INTO follows VALUES(?,?)').run(user.id,body.author);
   else db.prepare('DELETE FROM follows WHERE uid=? AND author=?').run(user.id,body.author);
  }else if(route==='/api/vote'){
   if(![-1,0,1].includes(body.score)||typeof body.video!=='string'||!db.prepare('SELECT 1 FROM videos WHERE id=?').get(body.video))fail(400,'Некорректная оценка');
   db.prepare('INSERT OR REPLACE INTO votes VALUES(?,?,?)').run(user.id,body.video,body.score);
  }else fail(404,'Не найдено');
  send({ok:true});
 }catch(err){if(res.headersSent||res.destroyed)return;const code=Number.isInteger(err.code)?err.code:500;
  res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify({error:code===500?'Ошибка сервера':err.message}));if(code===500)console.error(err)}
}).listen(Number(process.env.PORT||8080),process.env.HOST||'0.0.0.0');
