document.addEventListener('DOMContentLoaded', async () => {
  try {
    const data = await SFTMS.request('/api/dashboard'); const stats=data.stats;
    [['totalEvents','total_events'],['sensitiveEvents','sensitive_events'],['openAlerts','alerts'],['integrityViolations','integrity_violations'],['directories','directories'],['enabledPolicies','enabled_policies']].forEach(([id,key])=>{const el=document.getElementById(id);if(el)el.textContent=stats[key]});
    const c=data.charts; const render=(id,type,series,color)=>SFTMSCharts.render(id,type,series.map(x=>x.label),series.map(x=>x.value),color);
    render('activityChart','line',c.activity,'#41a6ff');render('eventChart','doughnut',c.events_by_type,['#41a6ff','#35d1bd','#f7b955','#a78bfa','#ff7285']);render('alertChart','doughnut',c.alerts_by_severity,['#ff7285','#f7b955','#41a6ff','#a78bfa']);render('integrityChart','doughnut',c.integrity,['#35d1bd','#ff7285','#f7b955','#41a6ff']);
    document.getElementById('recentEvents').innerHTML=data.recent_events.map(e=>`<tr><td>${SFTMS.time(e.timestamp)}</td><td>${SFTMS.escape(e.event_type)}</td><td title="${SFTMS.escape(e.destination_path||e.source_path||'')}">${SFTMS.escape(e.file_name)}</td><td>${SFTMS.risk(e.risk_level)}</td></tr>`).join('')||'<tr><td colspan="4" class="text-center text-secondary py-4">No monitoring events yet.</td></tr>';
    document.getElementById('serviceStatus').textContent=data.monitoring.state;document.getElementById('latestAlert').textContent=data.latest_alert?data.latest_alert.title:'No alerts recorded';
  } catch (error) { SFTMS.toast(error.message,'error'); }
});
