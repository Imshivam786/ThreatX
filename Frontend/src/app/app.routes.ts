import { Routes } from '@angular/router';
import { AddSystemComponent } from './components/add-system/add-system.component';
import { HomeComponent } from './components/home/home.component';
import { VisualizationComponent } from './components/visualization/visualization.component';

export const routes: Routes = [
  { path: '', redirectTo: '/home', pathMatch: 'full' },
  { path: 'home', component: HomeComponent },
  { path: 'visualization/:id', component: VisualizationComponent },
  { path: 'add-system', component: AddSystemComponent },
  { path: '**', redirectTo: '/home' }
];
