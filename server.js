'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const ROOT=__dirname, DATA=path.join(ROOT,'data','state.json'), PUBLIC=path.join(ROOT,'public');
const PORT=Number(process.env.PORT||3000), ADMIN_PASSWORD=process.env.TEACHER_PASSWORD, SECRET=process.env.SESSION_SECRET;
if(!ADMIN_PASSWORD||!SECRET||SECRET.length<24){console.error('Set TEACHER_PASSWORD and SESSION_SECRET (at least 24 chars) in environment.');process.exit(1)}
const NAMES=['Аскеров Давид','Әкімкерей Жанали','Байжанұлы Диар','Бахытжан Айым','Еркебұлан Мұхаммед','Жусупова Сымбат','Ихсанов Ильяс','Киржанов Абдуллах','Кулиев Арман','Қасымқанқызы Камилла','Құлбек Шаткүнім','Мәлік Нұрай','Менешов Бауыржан','Русланов Алишер','Сагингирей Алия','Самгат Елхан','Сарбалин Алимхан','Сейтқали Маруан','Серікұлы Аян','Шаймерленова Жасмин','Шамырханова Махаббат'];
const keys=['1a','1b','2a','2b','3a','3b','4a','4b','5a','5b','6a','6b'];
const max=[3,1,2,2,3,1,4,1,2,2,3,1];
const points=Object.fromEntries(keys.map((k,i)=>[k,max[i]]));
const rubric={
'1a':['Входные признаки и 3 входных нейрона','Скрытый слой из 3 и выходной из 2 с корректными подписями выходов','Подписи слоёв, связи и направление передачи'],
'1b':['Называет сеть многослойной и поясняет, что скрытый слой отсутствует у однослойного перцептрона'],
'2a':['Выбирает Sigmoid','Объясняет диапазон от 0 до 1 как оценку вероятности'],
'2b':['Выбирает ReLU','Объясняет, что ReLU сохраняет положительные значения и обнуляет отрицательные, а скачок даёт 0 или 1'],
'3a':['A: распознавание образов + корректный ожидаемый результат','Б: классификация + корректный ожидаемый результат','В: регрессия + числовой результат с единицей измерения'],
'3b':['Объясняет, что тип определяется характером результата, а система может решать разные задачи'],
'4a':['STT: речь/звук → текст','NLP: текст → смысл/намерение','GenAI: запрос → новый текст ответа','TTS: текст → озвученная речь'],
'4b':['Отвергает NLP/TTS как единственное решение; выбирает компьютерное зрение (CV) для изображения'],
'5a':['Отличает ошибку отдельного прогноза от правильного ответа','Функция потерь оценивает неточность прогнозов численно и направляет обучение'],
'5b':['Уменьшение потерь означает улучшение на обучающих данных','Не гарантирует новые данные; предлагает независимую проверку на ранее не использованных данных'],
'6a':['Прямой проход получает прогноз и далее оцениваются потери','Обратное распространение определяет влияние параметров/градиенты','Обновляют веса и смещения для уменьшения потерь'],
'6b':['Одного правильного примера недостаточно; нужно повторять обучение и проверять результат на разных/новых данных']};
function init(){if(fs.existsSync(DATA)) return JSON.parse(fs.readFileSync(DATA,'utf8'));return {open:false,published:false,students:NAMES.map((name,i)=>({id:String(i+1),name,variant:i%2+1,code:crypto.randomInt(100000,1000000).toString(),startedAt:null,finishedAt:null,answers:{},grade:null,reviewed:false})),audit:[]}}
let state=init();function save(){fs.mkdirSync(path.dirname(DATA),{recursive:true});let t=DATA+'.tmp';fs.writeFileSync(t,JSON.stringify(state,null,2));fs.renameSync(t,DATA)}if(!fs.existsSync(DATA))save();
function cookie(req){let s=(req.headers.cookie||'').split('; ').find(x=>x.startsWith('soch_auth='));return s?s.slice(10):''}
function token(role,id){let payload=Buffer.from(JSON.stringify({role,id,iat:Date.now()})).toString('base64url');return payload+'.'+crypto.createHmac('sha256',SECRET).update(payload).digest('base64url')}
function auth(req){try{let [p,s]=cookie(req).split('.');let mac=crypto.createHmac('sha256',SECRET).update(p).digest('base64url');if(s?.length!==mac.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(mac)))return null;let t=JSON.parse(Buffer.from(p,'base64url').toString());return Date.now()-t.iat<86400000?t:null}catch{return null}}
function putCookie(res,t){res.setHeader('Set-Cookie',`soch_auth=${t}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400${process.env.COOKIE_SECURE==='1'?'; Secure':''}`)}
function json(res,status,obj){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(obj))}
function studentView(s){let t=Date.now(),started=!!s.startedAt,finished=!!s.finishedAt||(started&&t>=s.startedAt+2400000);return {id:s.id,name:s.name,variant:s.variant,canStart:state.open&&!started,startedAt:s.startedAt,deadline:s.startedAt?s.startedAt+2400000:null,finished,answers:s.answers,grade:state.published?s.grade:null,reviewed:state.published?s.reviewed:false}}
function safeStudent(s){return {id:s.id,name:s.name,variant:s.variant,code:s.code,startedAt:s.startedAt,finishedAt:s.finishedAt,expired:!!s.startedAt&&Date.now()>=s.startedAt+2400000,grade:s.grade,reviewed:s.reviewed,answers:s.answers}}
function validAnswers(a){return Object.fromEntries(keys.map(k=>[k,typeof a?.[k]==='string'?a[k].slice(0,6000):'']))}
function escapedCSV(s){return '"'+String(s??'').replaceAll('"','""')+'"'}
function basicGrade(s){const a=s.answers, v=s.variant;let score={},notes={};function p(k,flags){score[k]=flags.filter(Boolean).length;notes[k]=flags.map((f,i)=>f?'✓ '+rubric[k][i]:'? '+rubric[k][i])}
const has=(k,re)=>re.test((a[k]||'').toLowerCase());
// Exact factual checks are a preliminary rubric-based assessment, NOT a validated final score for free text.
let q=a['1a']||'';p('1a',[/входн/i.test(q)&&/(3|три)/i.test(q),/скрыт/i.test(q)&&/выходн/i.test(q)&&/(3|три)/i.test(q)&&/(2|два)/i.test(q),/связ|стрел|направ|→/.test(q)]);
p('1b',[has('1b',/многослой|mlp|много.*сло/) && has('1b',/скрыт|однослойн/)]);
p('2a',[has('2a',/sigmoid|сигмоид/),has('2a',/0\s*(до|и|[-–—])\s*1|\[0\s*[,;]\s*1\]|от нул.*единиц/)]);
p('2b',[has('2b',/relu|р[еэ]лу/),has('2b',/положит|отрицат|нул/) && has('2b',/скач|0\s*(или|и)\s*1/)]);
p('3a',[has('3a',/распознаван/) && has('3a',v===1?/пешеход/:/растен/),has('3a',/классификац/) && has('3a',v===1?/опасн|безопасн/:/здоров|больн/),has('3a',/регресс/) && has('3a',v===1?/минут|врем/:/килограмм|кг|масс/)]);
p('3b',[has('3b',/разн|различ|отлич/) && has('3b',/результ|задач|тип/)]);
p('4a',[has('4a',/stt|распознаван.*реч/) && has('4a',/текст/),has('4a',/nlp/) && has('4a',/смысл|намерен/),has('4a',/genai|генератив/) && has('4a',/текст|ответ|объяснен/),has('4a',/tts/) && has('4a',/голос|реч|звук/)]);
p('4b',[has('4b',/компьютерн.*зрен|\bcv\b|computer vision/i)]);
p('5a',[has('5a',/ошибк/) && has('5a',/прогноз|предсказан|ответ/),has('5a',/функц.*потер|loss/) && has('5a',/числ|обучен|средн|оценк/)]);
p('5b',[has('5b',/обучающ|трениров|изученн/) && has('5b',/улучш|уменьш|сниз/),has('5b',/новых|тестов|неиспольз|валидац|провер/) && has('5b',/данн|пример|отзыв|сообщен/)]);
p('6a',[has('6a',/прям/) && has('6a',/прогноз|выход|предсказ/) && has('6a',/потер|ошиб/),has('6a',/обрат/) && has('6a',/градиент|влиян|производн|ошиб/),has('6a',/обнов|коррект|измен/) && has('6a',/вес|параметр|смещен/)]);
p('6b',[has('6b',/одного|один|одной|недостаточ/) && has('6b',/пример|ответ|прогноз|обнов/) && has('6b',/разн|нов|провер|продолж|много/)]);
return {score,notes,total:Object.values(score).reduce((a,b)=>a+b,0),source:'preliminary-rules',at:Date.now()}}
async function aiGrade(s){if(!process.env.OPENAI_API_KEY)return null;const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),25000);try{let r=await fetch('https://api.openai.com/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+process.env.OPENAI_API_KEY},body:JSON.stringify({model:process.env.OPENAI_MODEL||'gpt-4o-mini',temperature:0,response_format:{type:'json_object'},messages:[{role:'system',content:'Ты проверяющий СОЧ. Оцени СТРОГО по каждому отдельному дескриптору (0/1); учитывай эквивалентные формулировки и частично верные ответы. Не домысливай отсутствующие сведения. Ответ строго JSON {"score":{"1a":0,...},"notes":{"1a":"...",...}}. Для 1a ответ схемы задан текстовой структурой. Баллы за все критерии максимум 25. Все 12 ключей обязательны.'},{role:'user',content:JSON.stringify({variant:s.variant,descriptors:rubric,answers:s.answers})}]}),signal:controller.signal});if(!r.ok)throw Error('AI '+r.status);let data=await r.json();let x=JSON.parse(data.choices?.[0]?.message?.content||'{}');const score={};for(let k of keys){let n=Number(x.score?.[k]);if(!Number.isInteger(n)||n<0||n>points[k])throw Error('Invalid score '+k);score[k]=n}return {score,notes:x.notes||{},total:Object.values(score).reduce((a,b)=>a+b,0),source:'ai-preliminary',at:Date.now()}}catch(e){console.warn('AI grading unavailable:',e.message);return null}finally{clearTimeout(timer)}}
async function gradeNow(s){s.grade=basicGrade(s);save();let ai=await aiGrade(s);if(ai){s.grade=ai;save()}}
function finish(s){if(s.startedAt&&!s.finishedAt){s.finishedAt=Date.now();save();void gradeNow(s)}}
function syncDeadline(s){if(s.startedAt&&!s.finishedAt&&Date.now()>=s.startedAt+2400000)finish(s)}
async function main(req,res){try{let u=new URL(req.url,'http://localhost'),route=u.pathname;res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');if(req.method==='GET'&&!route.startsWith('/api/')){let fn=route==='/'?'index.html':route==='/teacher'?'teacher.html':route.slice(1);let target=path.resolve(PUBLIC,fn);if(!target.startsWith(PUBLIC+path.sep))return json(res,404,{error:'Not found'});let ext=path.extname(target);let mime={'.html':'text/html','.js':'application/javascript','.css':'text/css','.svg':'image/svg+xml'}[ext];if(!mime||!fs.existsSync(target))return json(res,404,{error:'Not found'});res.writeHead(200,{'Content-Type':mime+'; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});return fs.createReadStream(target).pipe(res)}
let body={};if(req.method!=='GET'){let text='';for await(let chunk of req){text+=chunk;if(text.length>100000) return json(res,413,{error:'Too large'})}try{body=JSON.parse(text||'{}')}catch{return json(res,400,{error:'Invalid JSON'})}}
let a=auth(req),admin=a?.role==='teacher',s=a?.role==='student'?state.students.find(x=>x.id===a.id):null;if(s)syncDeadline(s);
if(route==='/api/config'&&req.method==='GET')return json(res,200,{names:state.students.map(x=>({id:x.id,name:x.name})),timeLimit:2400});
if(route==='/api/login'&&req.method==='POST'){let st=state.students.find(x=>x.id===String(body.id));if(!st||st.code!==String(body.code))return json(res,401,{error:'Неверное имя или индивидуальный код'});putCookie(res,token('student',st.id));return json(res,200,{ok:true})}
if(route==='/api/teacher/login'&&req.method==='POST'){const x=Buffer.from(String(body.password||''));const y=Buffer.from(ADMIN_PASSWORD);if(x.length!==y.length||!crypto.timingSafeEqual(x,y))return json(res,401,{error:'Неверный пароль'});putCookie(res,token('teacher','admin'));return json(res,200,{ok:true})}
if(route==='/api/logout'&&req.method==='POST'){res.setHeader('Set-Cookie','soch_auth=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');return json(res,200,{ok:true})}
if(route==='/api/me'&&req.method==='GET')return json(res,200,{role:admin?'teacher':s?'student':null,state:s?studentView(s):null,open:state.open});
if(route==='/api/start'&&req.method==='POST'&&s){if(!state.open)return json(res,403,{error:'Учитель ещё не открыл доступ'});if(!s.startedAt){s.startedAt=Date.now();save()}syncDeadline(s);return json(res,200,studentView(s))}
if(route==='/api/save'&&req.method==='POST'&&s){if(!s.startedAt||s.finishedAt||Date.now()>=s.startedAt+2400000){syncDeadline(s);return json(res,403,{error:'Время истекло или работа не начата'})}s.answers=validAnswers(body.answers);save();return json(res,200,{ok:true,savedAt:Date.now()})}
if(route==='/api/submit'&&req.method==='POST'&&s){if(!s.startedAt)return json(res,403,{error:'Работа не начата'});if(!s.finishedAt){if(Date.now()<s.startedAt+2400000)s.answers=validAnswers(body.answers);finish(s)}return json(res,200,studentView(s))}
if(route==='/api/admin'&&req.method==='GET'&&admin){for(let st of state.students)syncDeadline(st);return json(res,200,{open:state.open,published:state.published,students:state.students.map(safeStudent),rubric,points})}
if(route==='/api/admin/toggle'&&req.method==='POST'&&admin){state.open=!!body.open;save();return json(res,200,{ok:true})}
if(route==='/api/admin/publish'&&req.method==='POST'&&admin){state.published=!!body.published;save();return json(res,200,{ok:true})}
if(route==='/api/admin/variant'&&req.method==='POST'&&admin){let st=state.students.find(x=>x.id===String(body.id));if(!st)return json(res,404,{error:'Not found'});if(st.startedAt)return json(res,409,{error:'Нельзя менять вариант после начала'});if(![1,2].includes(Number(body.variant)))return json(res,400,{error:'Bad variant'});st.variant=Number(body.variant);save();return json(res,200,{ok:true})}
if(route==='/api/admin/grade'&&req.method==='POST'&&admin){let st=state.students.find(x=>x.id===String(body.id));if(!st||!st.finishedAt)return json(res,400,{error:'Работа ещё не завершена'});let score={};for(let k of keys){let n=Number(body.score?.[k]);if(!Number.isInteger(n)||n<0||n>points[k])return json(res,400,{error:'Неверный балл '+k});score[k]=n}st.grade={score,total:Object.values(score).reduce((a,b)=>a+b,0),notes:st.grade?.notes||{},source:'teacher-confirmed',at:Date.now()};st.reviewed=true;save();return json(res,200,{ok:true})}
if(route==='/api/admin/csv'&&req.method==='GET'&&admin){let cols=['№','Ученик','Вариант','Статус',...keys,'Всего /25','Проверено учителем','Источник'];let lines=[cols,...state.students.map((s,i)=>[i+1,s.name,s.variant,s.finishedAt?'Завершено':s.startedAt?'Выполняет':'Ожидает',...keys.map(k=>s.grade?.score?.[k]??''),s.grade?.total??'',s.reviewed?'Да':'Нет',s.grade?.source??''])];res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="SOCH_11_results.csv"','Cache-Control':'no-store'});return res.end('\ufeff'+lines.map(r=>r.map(escapedCSV).join(';')).join('\r\n'))}
return json(res,a?404:401,{error:a?'Not found':'Требуется вход'});
}catch(e){console.error(e);return json(res,500,{error:'Ошибка сервера'})}}
http.createServer(main).listen(PORT,()=>console.log('SOCH11 running on http://localhost:'+PORT));
