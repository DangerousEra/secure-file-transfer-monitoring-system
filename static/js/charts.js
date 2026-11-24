/* Chart.js configuration shared by dashboard charts. */
window.SFTMSCharts = {
  instances: {},
  render(id, type, labels, values, color) {
    const canvas = document.getElementById(id); if (!canvas) return;
    this.instances[id]?.destroy();
    this.instances[id] = new Chart(canvas, {type, data:{labels, datasets:[{data:values,backgroundColor:color,borderColor:color,borderWidth:2,fill:type==='line',tension:.35}]}, options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:type==='doughnut',labels:{color:'#a8bed5',boxWidth:11,font:{size:10}}}},scales:type==='doughnut'?{}:{x:{ticks:{color:'#8ea8c3',font:{size:10}},grid:{display:false}},y:{beginAtZero:true,ticks:{color:'#8ea8c3',font:{size:10},precision:0},grid:{color:'rgba(111,145,180,.13)'}}}}});
  }
};
