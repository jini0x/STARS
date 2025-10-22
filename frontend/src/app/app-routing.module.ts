import {RouterModule, Routes} from '@angular/router';

import {ChatzoneComponent} from './chatzone/chatzone.component';
import {HeatmapComponent} from './heatmap/heatmap.component';
import {SecurityGatewayComponent} from './security-gateway/security-gateway.component';
import {NgModule} from '@angular/core';

const routes: Routes = [
  {path: '', component: ChatzoneComponent},
  {path: 'heatmap', component: HeatmapComponent},
  {path: 'security', component: SecurityGatewayComponent},
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
