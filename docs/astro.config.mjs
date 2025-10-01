// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://leaflock.app',
	integrations: [
		starlight({
			title: 'LeafLock',
			social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/RelativeSure/LeafLock' }],
			sidebar: [
				{
					label: 'Technical Reference',
					autogenerate: { directory: 'reference' },
				},
				{
					label: 'Getting Started',
					autogenerate: { directory: 'guides' },
				},
				{
					label: 'Deployment',
					autogenerate: { directory: 'deployment' },
				},
				{
					label: 'Development',
					autogenerate: { directory: 'development' },
				},
				{
					label: 'Administration',
					autogenerate: { directory: 'admin' },
				},
				{
					label: 'Troubleshooting',
					autogenerate: { directory: 'troubleshooting' },
				},
				{
					label: 'Legal',
					autogenerate: { directory: 'legal' },
				},
			],
		}),
	],
});
