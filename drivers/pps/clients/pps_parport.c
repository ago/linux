/*
 * pps_parport.c -- kernel parallel port PPS client
 *
 *
 * Copyright (C) 2009   Alexander Gordeev <lasaine@lvk.cs.msu.su>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


/*
 * TODO:
 * 1. try using SA_NODELAY for parport irq handler
 * 2. test under heavy load
 * 3. implement echo over SEL pin
 * 4. module parameters
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/irqnr.h>
#include <linux/time.h>
#include <linux/parport.h>
#include <linux/pps_kernel.h>

#define DRVNAME "pps_parport"
#define DRVDESC "parallel port PPS client"

/* maximum number of port reads when polling for signal clear */
#define RECEIVE_TIMEOUT	100

/* internal per port structure */
struct pps_client_pp {
	struct pardevice *pardev;	/* parport device */
	int source;			/* PPS source number */
};

#define SIGNAL_IS_SET(port) \
	((port->ops->read_status(port) & PARPORT_STATUS_ACK) != 0)

/* parport interrupt handler */
static void parport_irq(void *handle)
{
	struct pps_event_time ts_assert, ts_clear;
	struct pps_client_pp *dev = handle;
	struct parport *port = dev->pardev->port;
	int i;
	unsigned long flags;

	/* first of all we get the time stamp... */
	pps_get_ts(&ts_assert);

	/* check the signal (no signal means the pulse is lost this time) */
	if (!SIGNAL_IS_SET(port)) {
		pr_err(DRVNAME ": lost the signal\n");
		return;
	}

	/* FIXME: this is here until we have a fast interrupt */
	local_irq_save(flags);
	/* poll the port until the signal is unset */
	for (i = RECEIVE_TIMEOUT; i; i--)
		if (!SIGNAL_IS_SET(port)) {
			pps_get_ts(&ts_clear);
			local_irq_restore(flags);

			/* FIXME: move these two calls to workqueue? */
			/* fire assert event */
			pps_event(dev->source, &ts_assert,
					PPS_CAPTUREASSERT, NULL);
			/* fire clear event */
			pps_event(dev->source, &ts_clear,
					PPS_CAPTURECLEAR, NULL);

			return;
		}
	local_irq_restore(flags);

	/* timeout */
	pr_err(DRVNAME ": timeout in interrupt handler while waiting"
			" for signal clear\n");
}

/* the PPS echo function */
static void pps_echo(int source, int event, void *data)
{
	pr_info("echo %s %s for source %d\n",
		event & PPS_CAPTUREASSERT ? "assert" : "",
		event & PPS_CAPTURECLEAR ? "clear" : "",
		source);
}

static void parport_attach(struct parport *port)
{
	struct pps_client_pp *device;
	struct pps_source_info info = {
		.name		= DRVNAME,
		.path		= "",
		.mode		= PPS_CAPTUREBOTH | \
				  PPS_OFFSETASSERT | PPS_OFFSETCLEAR | \
				  PPS_ECHOASSERT | PPS_ECHOCLEAR | \
				  PPS_CANWAIT | PPS_TSFMT_TSPEC,
		.echo 		= pps_echo,
		.owner		= THIS_MODULE,
	};

	device = kzalloc(sizeof(struct pps_client_pp), GFP_KERNEL);
	if (!device) {
		pr_err(DRVNAME ": memory allocation failed, not attaching\n");
		return;
	}

	device->pardev = parport_register_device(port, DRVNAME,
			NULL, NULL, parport_irq, 0, device);
	if (!device->pardev) {
		pr_err(DRVNAME ": couldn't register with %s\n", port->name);
		goto err_free;
	}

	if (parport_claim_or_block(device->pardev) < 0) {
		pr_err(DRVNAME ": couldn't claim %s\n", port->name);
		goto err_unregister_dev;
	}

	device->source = pps_register_source(&info,
			PPS_CAPTUREBOTH | PPS_OFFSETASSERT | PPS_OFFSETCLEAR);
	if (device->source < 0) {
		pr_err(DRVNAME ": couldn't register PPS source\n");
		goto err_release_dev;
	}

	port->ops->enable_irq(port);

	pr_info(DRVNAME ": attached to %s\n", port->name);

	return;

err_release_dev:
	parport_release(device->pardev);
err_unregister_dev:
	parport_unregister_device(device->pardev);
err_free:
	kfree(device);
}

static void parport_detach(struct parport *port)
{
	struct pardevice *pardev = port->cad;
	struct pps_client_pp *device;

	/* oooh, this is ugly! */
	if (strcmp(pardev->name, DRVNAME))
		/* not our port */
		return;

	device = pardev->private;

	port->ops->disable_irq(port);
	pps_unregister_source(device->source);
	parport_release(pardev);
	parport_unregister_device(pardev);
	kfree(device);
}

static struct parport_driver pps_parport_driver = {
	.name = DRVNAME,
	.attach = parport_attach,
	.detach = parport_detach,
};

/* module staff */

static int __init pps_parport_init(void)
{
	int ret;

	pr_info(DRVNAME ": " DRVDESC "\n");

	ret = parport_register_driver(&pps_parport_driver);
	if (ret) {
		pr_err(DRVNAME ": unable to register with parport\n");
		return ret;
	}

	return  0;
}

static void __exit pps_parport_exit(void)
{
	parport_unregister_driver(&pps_parport_driver);
}

module_init(pps_parport_init);
module_exit(pps_parport_exit);

MODULE_AUTHOR("Alexander Gordeev <lasaine@lvk.cs.msu.su>");
MODULE_DESCRIPTION(DRVDESC);
MODULE_LICENSE("GPL");
