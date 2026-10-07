import { chromium } from '/home/muhajirin/shared-docs/node_modules/playwright/index.mjs';
const browser = await chromium.launch({headless:true,executablePath:'/home/muhajirin/.cache/ms-playwright/chromium-1243/chrome-linux-arm64/chrome',args:['--no-sandbox']});
try {
  const page=await browser.newPage(); const errors=[];
  page.on('pageerror',e=>errors.push(String(e)));
  await page.goto('http://127.0.0.1:7997/',{waitUntil:'domcontentloaded'});
  const dismiss=page.locator('button[aria-label="Close camera setup"]');
  if (await dismiss.count()) await dismiss.click();
  await page.locator('.modal-overlay').waitFor({state:'hidden'});
  await page.locator('#recording-token').fill(process.env.QA_TOKEN);
  await page.locator('#recording-camera').fill('onvif:synthetic');
  await page.locator('#recording-from').fill('2026-10-04T19:00');
  await page.locator('#recording-to').fill('2026-10-04T21:00');
  await page.locator('#recording-load').click();
  await page.waitForTimeout(1500);
  console.log('coverageStatus='+await page.locator('#recording-status').textContent());
  await page.locator('#recording-timeline button').first().waitFor({timeout:15000});
  const intervals=await page.locator('#recording-timeline button').count();
  await page.locator('#recording-timeline button').first().click();
  await page.waitForFunction(()=>document.querySelector('#recording-video').currentTime>0.4,{timeout:25000});
  const first=await page.locator('#recording-video').evaluate(v=>({currentTime:v.currentTime,duration:v.duration,readyState:v.readyState,videoWidth:v.videoWidth}));
  await page.locator('#recording-video').evaluate(v=>{v.currentTime=4});
  await page.waitForTimeout(1800);
  const second=await page.locator('#recording-video').evaluate(v=>({currentTime:v.currentTime,duration:v.duration,readyState:v.readyState,videoWidth:v.videoWidth}));
  console.log(JSON.stringify({intervals,first,second,errors,status:await page.locator('#recording-status').textContent()}));
  if(intervals!==1 || first.videoWidth===0 || second.currentTime<4.5 || errors.length)process.exitCode=1;
  await page.locator('#recording-live').click();
  console.log('liveReturn='+await page.locator('#recording-status').textContent());
}finally{await browser.close();}
