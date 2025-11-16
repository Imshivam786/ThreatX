import { Chart, registerables } from 'chart.js';

// Register Chart.js components
Chart.register(...registerables);

export const chartDefaults = {
  responsive: true,
  maintainAspectRatio: false,
  animation: {
    duration: 750
  }
};
