/* bluetooth_att_server_attributes_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#include "bluetooth_att_server_attributes_dialog.h"
#include <ui_bluetooth_att_server_attributes_dialog.h>

#include <ui/qt/utils/color_utils.h>

#include "epan/epan.h"
#include "epan/to_str.h"
#include "epan/epan_dissect.h"
#include "epan/prefs.h"
#include "epan/dissectors/packet-bluetooth.h"
#include "epan/dissectors/packet-btatt.h"

#include "ui/simple_dialog.h"

#include <QClipboard>
#include <QContextMenuEvent>
#include <QPushButton>
#include <QTreeWidget>
#include <QFileDialog>

static const int column_number_handle = 0;
static const int column_number_uuid = 1;
static const int column_number_uuid_name = 2;

static gboolean
btatt_handle_tap_packet(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *edt, const void* data)
{
    tapinfo_t *tapinfo = (tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_packet)
        tapinfo->tap_packet(tapinfo, pinfo, edt, data);

    return TRUE;
}

static void
btatt_handle_tap_reset(void *tapinfo_ptr)
{
    tapinfo_t *tapinfo = (tapinfo_t *) tapinfo_ptr;

    if (tapinfo->tap_reset)
        tapinfo->tap_reset(tapinfo);
}

BluetoothAttServerAttributesDialog::BluetoothAttServerAttributesDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    ui(new Ui::BluetoothAttServerAttributesDialog)
{
    ui->setupUi(this);
    loadGeometry(parent.width() * 4 / 5, parent.height() * 2 / 3);

    connect(ui->tableTreeWidget, SIGNAL(customContextMenuRequested(const QPoint &)), this, SLOT(tableContextMenu(const QPoint &)));
    connect(ui->interfaceComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(interfaceCurrentIndexChanged(int)));
    connect(ui->deviceComboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(deviceCurrentIndexChanged(int)));
    connect(ui->removeDuplicatesCheckBox, SIGNAL(stateChanged(int)), this, SLOT(removeDuplicatesStateChanged(int)));

    ui->tableTreeWidget->sortByColumn(column_number_handle, Qt::AscendingOrder);

    ui->tableTreeWidget->setStyleSheet("QTreeView::item:hover{background-color:lightyellow; color:black;}");

    context_menu_.addActions(QList<QAction *>() << ui->actionMark_Unmark_Cell);
    context_menu_.addActions(QList<QAction *>() << ui->actionMark_Unmark_Row);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_Cell);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_Rows);
    context_menu_.addActions(QList<QAction *>() << ui->actionCopy_All);
    context_menu_.addActions(QList<QAction *>() << ui->actionSave_as_image);

    tapinfo_.tap_packet = tapPacket;
    tapinfo_.tap_reset  = tapReset;
    tapinfo_.ui = this;

    registerTapListener("btatt.handles", &tapinfo_, NULL,
                        0,
                        btatt_handle_tap_reset,
                        btatt_handle_tap_packet,
                        NULL
                        );

    cap_file_.retapPackets();
}


BluetoothAttServerAttributesDialog::~BluetoothAttServerAttributesDialog()
{
    delete ui;
}


void BluetoothAttServerAttributesDialog::captureFileClosing()
{
    ui->interfaceComboBox->setEnabled(FALSE);
    ui->deviceComboBox->setEnabled(FALSE);
    ui->removeDuplicatesCheckBox->setEnabled(FALSE);

    WiresharkDialog::captureFileClosing();
}


void BluetoothAttServerAttributesDialog::changeEvent(QEvent *event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            ui->retranslateUi(this);
            break;
        default:
            break;
        }
    }
    QDialog::changeEvent(event);
}


void BluetoothAttServerAttributesDialog::keyPressEvent(QKeyEvent *event)
{
/* NOTE: Do nothing*, but in real it "takes focus" from button_box so allow user
 * to use Enter button to jump to frame from tree widget */
/* * - reimplement shortcuts from contex menu */

   if (event->modifiers() & Qt::ControlModifier && event->key()== Qt::Key_M)
        on_actionMark_Unmark_Row_triggered();
}


void BluetoothAttServerAttributesDialog::tableContextMenu(const QPoint &pos)
{
    context_menu_.exec(ui->tableTreeWidget->viewport()->mapToGlobal(pos));
}


void BluetoothAttServerAttributesDialog::on_actionMark_Unmark_Cell_triggered()
{
    QBrush fg;
    QBrush bg;

    if (ui->tableTreeWidget->currentItem()->background(ui->tableTreeWidget->currentColumn()) == QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg))) {
        fg = QBrush();
        bg = QBrush();
    } else {
        fg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_fg));
        bg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg));
    }

    ui->tableTreeWidget->currentItem()->setForeground(ui->tableTreeWidget->currentColumn(), fg);
    ui->tableTreeWidget->currentItem()->setBackground(ui->tableTreeWidget->currentColumn(), bg);
}


void BluetoothAttServerAttributesDialog::on_actionMark_Unmark_Row_triggered()
{
    QBrush fg;
    QBrush bg;
    bool   is_marked = TRUE;

    for (int i = 0; i < ui->tableTreeWidget->columnCount(); i += 1) {
        if (ui->tableTreeWidget->currentItem()->background(i) != QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg)))
            is_marked = FALSE;
    }

    if (is_marked) {
        fg = QBrush();
        bg = QBrush();
    } else {
        fg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_fg));
        bg = QBrush(ColorUtils::fromColorT(&prefs.gui_marked_bg));
    }

    for (int i = 0; i < ui->tableTreeWidget->columnCount(); i += 1) {
        ui->tableTreeWidget->currentItem()->setForeground(i, fg);
        ui->tableTreeWidget->currentItem()->setBackground(i, bg);
    }
}


void BluetoothAttServerAttributesDialog::on_actionCopy_Cell_triggered()
{
    QClipboard             *clipboard = QApplication::clipboard();
    QString                 copy;

    copy = QString(ui->tableTreeWidget->currentItem()->text(ui->tableTreeWidget->currentColumn()));

    clipboard->setText(copy);
}


void BluetoothAttServerAttributesDialog::on_actionCopy_Rows_triggered()
{
    QClipboard                         *clipboard = QApplication::clipboard();
    QString                             copy;
    QList<QTreeWidgetItem *>            items;
    QList<QTreeWidgetItem *>::iterator  i_item;

    items =  ui->tableTreeWidget->selectedItems();

    for (i_item = items.begin(); i_item != items.end(); ++i_item) {
        copy += QString("%1  %2  %3\n")
                .arg((*i_item)->text(column_number_handle), -6)
                .arg((*i_item)->text(column_number_uuid), -32)
                .arg((*i_item)->text(column_number_uuid_name));

    }

    clipboard->setText(copy);
}

void BluetoothAttServerAttributesDialog::tapReset(void *tapinfo_ptr)
{
    tapinfo_t *tapinfo = (tapinfo_t *) tapinfo_ptr;
    BluetoothAttServerAttributesDialog  *bluetooth_att_server_attributes_dialog = static_cast<BluetoothAttServerAttributesDialog *>(tapinfo->ui);


    bluetooth_att_server_attributes_dialog->ui->tableTreeWidget->clear();
}


gboolean BluetoothAttServerAttributesDialog::tapPacket(void *tapinfo_ptr, packet_info *pinfo, epan_dissect_t *, const void *data)
{
    tapinfo_t                           *tapinfo     = static_cast<tapinfo_t *>(tapinfo_ptr);
    BluetoothAttServerAttributesDialog  *dialog      = static_cast<BluetoothAttServerAttributesDialog *>(tapinfo->ui);
    tap_handles_t                       *tap_handles = static_cast<tap_handles_t *>(const_cast<void *>(data));
    QString                              handle;
    QString                              uuid;
    QString                              uuid_name;
    gchar                               *addr = NULL;

    if (dialog->file_closed_)
        return FALSE;

    if (pinfo->rec->rec_type != REC_TYPE_PACKET)
        return FALSE;

    if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
        gchar       *interface;
        const char  *interface_name;

        interface_name = epan_get_interface_name(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id);
        interface = wmem_strdup_printf(wmem_packet_scope(), "%u: %s", pinfo->rec->rec_header.packet_header.interface_id, interface_name);

        if (dialog->ui->interfaceComboBox->findText(interface) == -1)
            dialog->ui->interfaceComboBox->addItem(interface);

        if (interface && dialog->ui->interfaceComboBox->currentIndex() > 0) {
            if (dialog->ui->interfaceComboBox->currentText() != interface)
            return TRUE;
        }
    }

    if (pinfo->p2p_dir == P2P_DIR_SENT || pinfo->p2p_dir == P2P_DIR_RECV)
        addr = address_to_str(wmem_packet_scope(), &pinfo->src);

    if (addr && dialog->ui->deviceComboBox->findText(addr) == -1) {
        dialog->ui->deviceComboBox->addItem(addr);
    }

    if (addr && dialog->ui->deviceComboBox->currentIndex() > 0) {
        if (dialog->ui->deviceComboBox->currentText() != addr)
            return TRUE;
    }

    handle.sprintf("0x%04x", tap_handles->handle);
    uuid = QString(print_numeric_uuid(&tap_handles->uuid));
    uuid_name = QString(print_uuid(&tap_handles->uuid));

    if (dialog->ui->removeDuplicatesCheckBox->checkState() == Qt::Checked) {
        QTreeWidgetItemIterator i_item(dialog->ui->tableTreeWidget);

        while (*i_item) {
            QTreeWidgetItem *item = static_cast<QTreeWidgetItem*>(*i_item);

            if (item->text(column_number_handle) == handle &&
                    item->text(column_number_uuid) == uuid &&
                    item->text(column_number_uuid_name) == uuid_name)
                return TRUE;
            ++i_item;
        }
    }

    QTreeWidgetItem *item = new QTreeWidgetItem(dialog->ui->tableTreeWidget);
    item->setText(column_number_handle, handle);
    item->setText(column_number_uuid, uuid);
    item->setText(column_number_uuid_name,  uuid_name);
    item->setData(0, Qt::UserRole, QVariant::fromValue(pinfo->num));

    for (int i = 0; i < dialog->ui->tableTreeWidget->columnCount(); i++) {
        dialog->ui->tableTreeWidget->resizeColumnToContents(i);
    }

    return TRUE;
}

void BluetoothAttServerAttributesDialog::interfaceCurrentIndexChanged(int)
{
    cap_file_.retapPackets();
}


void BluetoothAttServerAttributesDialog::deviceCurrentIndexChanged(int)
{
    cap_file_.retapPackets();
}


void BluetoothAttServerAttributesDialog::removeDuplicatesStateChanged(int)
{
    cap_file_.retapPackets();
}



void BluetoothAttServerAttributesDialog::on_tableTreeWidget_itemActivated(QTreeWidgetItem *item, int)
{
    if (file_closed_)
        return;

    guint32 frame_number = item->data(0, Qt::UserRole).value<guint32>();

    emit goToPacket(frame_number);
}


void BluetoothAttServerAttributesDialog::on_actionCopy_All_triggered()
{
    QClipboard             *clipboard = QApplication::clipboard();
    QString                 copy;
    QTreeWidgetItemIterator i_item(ui->tableTreeWidget);

    copy = QString("%1  %2  %3\n")
            .arg(ui->tableTreeWidget->headerItem()->text(column_number_handle), -6)
            .arg(ui->tableTreeWidget->headerItem()->text(column_number_uuid), -32)
            .arg(ui->tableTreeWidget->headerItem()->text(column_number_uuid_name));

    while (*i_item) {
        QTreeWidgetItem *item = static_cast<QTreeWidgetItem*>(*i_item);
        copy += QString("%1  %2  %3\n")
                .arg(item->text(column_number_handle), -6)
                .arg(item->text(column_number_uuid), -32)
                .arg(item->text(column_number_uuid_name));
        ++i_item;
    }

    clipboard->setText(copy);
}

void BluetoothAttServerAttributesDialog::on_actionSave_as_image_triggered()
{
    QPixmap image;

    QString fileName = QFileDialog::getSaveFileName(this, tr("Save Table Image"),
                           "att_server_attributes_table.png",
                           tr("PNG Image (*.png)"));

    if (fileName.isEmpty()) return;

    image = QPixmap::grabWidget(ui->tableTreeWidget);
    image.save(fileName, "PNG");
}

void BluetoothAttServerAttributesDialog::on_buttonBox_clicked(QAbstractButton *)
{
/*    if (button == foo_button_) */
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
